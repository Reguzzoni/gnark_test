package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnark_mimc "github.com/consensys/gnark/std/hash/mimc"
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
	h, _ := gnark_mimc.NewMiMC(api)
	var totalSum frontend.Variable = 0

	for idx := 0; idx < MaxValues; idx++ {

		totalSum = api.Add(totalSum, c.Values[idx])

		h.Reset()
		h.Write(c.Values[idx])
		currentHash := h.Sum()

		for idxTree := 0; idxTree < TreeDepth; idxTree++ {
			// check se sx o dx path albero
			left := api.Select(c.IsRight[idx][idxTree], currentHash, c.Paths[idx][idxTree])
			right := api.Select(c.IsRight[idx][idxTree], c.Paths[idx][idxTree], currentHash)

			h.Reset()
			h.Write(left, right)
			currentHash = h.Sum()
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

	// costruzione tree
	var scaledValues [MaxValues]int64
	var leaves [][]byte
	hFunc := mimc.NewMiMC()

	for idxValue := 0; idxValue < MaxValues; idxValue++ {
		if idxValue < len(data.Values) {
			scaledValues[idxValue] = int64(math.Round(data.Values[idxValue] * 1000))
		}

		var e fr.Element
		e.SetInt64(scaledValues[idxValue])

		hFunc.Reset()
		hFunc.Write(e.Marshal())
		hashByte := hFunc.Sum(nil)

		var leafElement fr.Element
		leafElement.SetBytes(hashByte)
		leaves = append(leaves, leafElement.Marshal())
	}

	tree := make([][][]byte, TreeDepth+1)
	tree[0] = leaves
	for idxTree := 0; idxTree < TreeDepth; idxTree++ {
		var level [][]byte
		for idxTreeLevel := 0; idxTreeLevel < len(tree[idxTree]); idxTreeLevel += 2 {
			hFunc.Reset()
			hFunc.Write(tree[idxTree][idxTreeLevel])
			hFunc.Write(tree[idxTree][idxTreeLevel+1])
			level = append(level, hFunc.Sum(nil))
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

	fmt.Println("🚀 File JSON generati con successo per SnarkJS!")
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

// func exportForSnarkJS(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness) {
// 	p := proof.(*gnark_bn254.Proof)
// 	v := vk.(*gnark_bn254.VerifyingKey)

// 	witnessValues, _ := publicWitness.MarshalBinary()
// 	var vec []fr.Element
// 	// Parse the marshaled witness to extract public values
// 	// For a witness with 2 public variables (ExpectedSum, Root)
// 	expectedSumBytes := witnessValues[0:32]
// 	rootBytes := witnessValues[32:64]

// 	var expectedSumElement, rootElement fr.Element
// 	expectedSumElement.SetBytes(expectedSumBytes)
// 	rootElement.SetBytes(rootBytes)

// 	vec = []fr.Element{expectedSumElement, rootElement}

// 	publicSignals := []string{
// 		vec[0].String(), // ExpectedSum
// 		vec[1].String(), // Root
// 	}
// 	// Estrarre i punti IC (Input Commitment)
// 	// In Gnark BN254, i punti della VK per gli input pubblici sono in v.G1.K
// 	ic := [][]string{}
// 	for _, pt := range v.G1.K {
// 		ic = append(ic, []string{
// 			pt.X.String(),
// 			pt.Y.String(),
// 			"1",
// 		})
// 	}

// 	// Costruzione della Mappa per la Verification Key
// 	vkMap := map[string]interface{}{
// 		"protocol":   "groth16",
// 		"curve":      "bn128", // SnarkJS usa questo nome per BN254
// 		"nPublic":    2,
// 		"vk_alpha_1": []string{v.G1.Alpha.X.String(), v.G1.Alpha.Y.String(), "1"},
// 		"vk_beta_2": [][]string{
// 			{v.G2.Beta.X.A1.String(), v.G2.Beta.X.A0.String()},
// 			{v.G2.Beta.Y.A1.String(), v.G2.Beta.Y.A0.String()},
// 			{"1", "0"},
// 		},
// 		"vk_gamma_2": [][]string{
// 			{v.G2.Gamma.X.A1.String(), v.G2.Gamma.X.A0.String()},
// 			{v.G2.Gamma.Y.A1.String(), v.G2.Gamma.Y.A0.String()},
// 			{"1", "0"},
// 		},
// 		"vk_delta_2": [][]string{
// 			{v.G2.Delta.X.A1.String(), v.G2.Delta.X.A0.String()},
// 			{v.G2.Delta.Y.A1.String(), v.G2.Delta.Y.A0.String()},
// 			{"1", "0"},
// 		},
// 		"IC": ic,
// 	}

// 	// 1. Salvataggio verification_key.json
// 	writeJSON("verification_key.json", vkMap)

// 	// 2. Salvataggio proof.json
// 	proofMap := map[string]interface{}{
// 		"pi_a": []string{p.Ar.X.String(), p.Ar.Y.String(), "1"},
// 		"pi_b": [][]string{
// 			{p.Bs.X.A1.String(), p.Bs.X.A0.String()},
// 			{p.Bs.Y.A1.String(), p.Bs.Y.A0.String()},
// 			{"1", "0"},
// 		},
// 		"pi_c":     []string{p.Krs.X.String(), p.Krs.Y.String(), "1"},
// 		"protocol": "groth16",
// 		"curve":    "bn128",
// 	}
// 	writeJSON("proof.json", proofMap)

// 	// sumStr := fmt.Sprintf("%d", sum)
// 	// rootStr := root.String()

// 	// 3. Salvataggio public.json
// 	// publicSignals := []string{
// 	// 	sumStr,
// 	// 	rootStr, // E la Root dopo
// 	// }
// 	writeJSON("public.json", publicSignals)

// 	fmt.Println("File caricaati")

// }

// func writeJSON(name string, data interface{}) {
// 	f, _ := os.Create(name)
// 	enc := json.NewEncoder(f)
// 	enc.SetIndent("", "  ")
// 	enc.Encode(data)
// }
