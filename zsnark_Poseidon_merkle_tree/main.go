package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidon2_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnark_poseidon2 "github.com/consensys/gnark/std/permutation/poseidon2"
	gnarktosnarkjs "github.com/mysteryon88/gnark-to-snarkjs"
)

const (
	MaxValues = 128 // provo a usare 128 come valore esponenziale di 2, let s try!
	TreeDepth = 7
)

type InputData struct {
	Values []float64 `json:"values"`
}

type QuantumValueCircuit struct {
	Root        frontend.Variable                       `gnark:",public"`
	ExpectedSum frontend.Variable                       `gnark:",public"`
	Values      [MaxValues]frontend.Variable            `gnark:",secret"`
	Paths       [MaxValues][TreeDepth]frontend.Variable `gnark:",secret"`
	IsRight     [MaxValues][TreeDepth]frontend.Variable `gnark:",secret"` // 1 se il path è a destra, 0 se a sinistra
}

func (c *QuantumValueCircuit) Define(api frontend.API) error {
	// 1. Inizializza con FromParameters.
	// Larghezza (width) = 2 è l'ideale per un Merkle Tree (2 input -> 1 output)
	// 8 full rounds e 56 partial rounds sono standard per BN254 width 2
	p2, err := gnark_poseidon2.NewPoseidon2FromParameters(api, 2, 8, 56)
	if err != nil {
		return err
	}

	var totalSum frontend.Variable = 0

	for idx := 0; idx < MaxValues; idx++ {
		totalSum = api.Add(totalSum, c.Values[idx])

		// 2. Hash della foglia (Width 2: passiamo il valore e uno zero come padding)
		stateLeaf := []frontend.Variable{c.Values[idx], 0}
		p2.Permutation(stateLeaf)
		currentHash := stateLeaf[0] // Prendiamo il primo elemento come digest

		for idxTree := 0; idxTree < TreeDepth; idxTree++ {
			left := api.Select(c.IsRight[idx][idxTree], currentHash, c.Paths[idx][idxTree])
			right := api.Select(c.IsRight[idx][idxTree], c.Paths[idx][idxTree], currentHash)

			// 3. Hash del nodo (Width 2: left e right)
			stateNode := []frontend.Variable{left, right}
			p2.Permutation(stateNode)
			currentHash = stateNode[0]
		}
		api.AssertIsEqual(currentHash, c.Root)
	}

	api.AssertIsEqual(totalSum, c.ExpectedSum)
	return nil
}

func main() {
	// crea cistom ciurcuit
	var myCircuit QuantumValueCircuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	pk, vk, _ := groth16.Setup(ccs)

	// valori scalari, attenzione che zkstark NON gestisce i float, quindi scala

	// Dati JSON  esempio
	jsonData := `{"values": [1.3, 2.3, 4.234]}`
	var data InputData
	json.Unmarshal([]byte(jsonData), &data)

	// 1. Inizializzazione della permutazione Poseidon2
	// t=2 (width), rf=8 (full rounds), rp=56 (partial rounds)
	p2Instance := poseidon2_bn254.NewPermutation(2, 8, 56)

	var scaledValues [MaxValues]int64
	leaves := make([][]byte, MaxValues)

	for idxValue := 0; idxValue < MaxValues; idxValue++ {
		if idxValue < len(data.Values) {
			scaledValues[idxValue] = int64(math.Round(data.Values[idxValue] * 1000))
		}

		var e fr.Element
		e.SetInt64(scaledValues[idxValue])

		// 2. Hash della foglia: [valore, 0]
		state := []fr.Element{e, {}}

		// CHIAMATA CORRETTA: metodo sull'istanza
		err := p2Instance.Permutation(state)
		if err != nil {
			panic(err)
		}

		// Prendiamo il primo elemento come digest
		leaves[idxValue] = state[0].Marshal()
	}

	// 3. Costruzione dell'albero
	tree := make([][][]byte, TreeDepth+1)
	tree[0] = leaves
	for idxTree := 0; idxTree < TreeDepth; idxTree++ {
		var level [][]byte
		for idxTreeLevel := 0; idxTreeLevel < len(tree[idxTree]); idxTreeLevel += 2 {

			var left, right fr.Element
			left.SetBytes(tree[idxTree][idxTreeLevel])
			right.SetBytes(tree[idxTree][idxTreeLevel+1])

			// 4. Hash del nodo: [left, right]
			nodeState := []fr.Element{left, right}

			// CHIAMATA CORRETTA: metodo sull'istanza
			p2Instance.Permutation(nodeState)

			level = append(level, nodeState[0].Marshal())
		}
		tree[idxTree+1] = level
	}
	root := tree[TreeDepth][0]

	var assignment QuantumValueCircuit
	assignment.Root = root
	var sum int64 = 0

	for i := 0; i < MaxValues; i++ {
		assignment.Values[i] = scaledValues[i]
		sum += scaledValues[i]

		currIdx := i
		for d := 0; d < TreeDepth; d++ {
			if currIdx%2 == 0 {
				assignment.Paths[i][d] = tree[d][currIdx+1]
				assignment.IsRight[i][d] = 1
			} else {
				assignment.Paths[i][d] = tree[d][currIdx-1]
				assignment.IsRight[i][d] = 0
			}
			currIdx /= 2
		}
	}
	assignment.ExpectedSum = sum

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	fmt.Println("public witness ", publicWitness)

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Printf("Errore: %v\n", err)
		return
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err == nil {
		fmt.Printf("Somma verificata: %d su %d slot.\n", sum, MaxValues)
	}

	var rootElement fr.Element
	rootElement.SetBytes(root)

	//exportForSnarkJS(proof, vk, publicWitness)
	// exportBinaryForRust(proof, vk, publicWitness)
	exportForSnark(proof, vk, publicWitness)
}

func exportForSnark(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness) {
	// 1. Estraiamo i valori dal Witness Pubblico
	// Gnark ordina alfabeticamente: [0] = ExpectedSum, [1] = Root
	pubVals := publicWitness.Vector()
	// Convertiamo il vettore in uno slice di fr.Element leggibile
	// fr.Vector implementa l'interfaccia per essere convertito così:
	vec := pubVals.(fr.Vector)

	// Adesso accediamo agli elementi con l'indice
	// In Gnark l'ordine è alfabetico: ExpectedSum (0), Root (1)
	sumStr := vec[0].String()
	rootStr := vec[1].String()

	// Creiamo l'array di stringhe che SnarkJS si aspetta
	publicSignals := []string{
		sumStr,
		rootStr,
	}

	// 2. Esportiamo la Proof (con cast a BN254 richiesto dalla libreria)
	proofOut, err := os.Create("proof.json")
	if err == nil {
		// La libreria richiede il puntatore specifico della curva BN254
		gnarktosnarkjs.ExportProof(proof.(*groth16_bn254.Proof), publicSignals, proofOut)
		proofOut.Close()
	}

	// 3. Esportiamo la Verifying Key
	vkOut, err := os.Create("verification_key.json")
	if err == nil {
		// La libreria richiede il puntatore specifico della curva BN254
		gnarktosnarkjs.ExportVerifyingKey(vk.(*groth16_bn254.VerifyingKey), vkOut)
		vkOut.Close()
	}

	// 4. Esportiamo il file public.json (Fondamentale per SnarkJS!)
	publicOut, err := os.Create("public.json")
	if err == nil {
		enc := json.NewEncoder(publicOut)
		enc.SetIndent("", "  ")
		enc.Encode(publicSignals)
		publicOut.Close()
	}

	fmt.Println(" File JSON generati con successo per SnarkJS!")
	fmt.Printf("   Signals: Sum=%s, Root=%s\n", sumStr, rootStr)
}

func exportBinaryForRust(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness) {

	fProof, _ := os.Create("proof.bin")
	proof.WriteTo(fProof)

	fVk, _ := os.Create("vk.bin")
	vk.WriteTo(fVk)

	fPub, _ := os.Create("public_witness.bin")
	publicWitness.WriteTo(fPub)

}
