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
	Hashes      [MaxValues]frontend.Variable `gnark:",public"`
	ExpectedSum frontend.Variable            `gnark:",public"`

	Values [MaxValues]frontend.Variable `gnark:",secret"`
}

func (c *QuantumValueCircuit) Define(api frontend.API) error {
	p2, _ := gnark_poseidon2.NewPoseidon2FromParameters(api, 2, 8, 56)
	totalSum := frontend.Variable(0)

	for i := 0; i < MaxValues; i++ {
		// Accumulo la somma
		totalSum = api.Add(totalSum, c.Values[i])

		// Verifico l'hash del singolo KPI (Mapping Lineare)
		state := []frontend.Variable{c.Values[i], 0} // [valore, padding]
		p2.Permutation(state)

		// Questo vincolo assicura la provenienza del dato
		api.AssertIsEqual(state[0], c.Hashes[i])
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
	jsonData := `{
		"values": [
			1.3, 2.3, 4.234, 3.87, 5.12, 6.45, 7.01, 6.88,
			5.76, 4.92, 3.58, 2.91, 3.14, 4.01, 5.33, 6.02,
			6.77, 7.25, 8.1, 7.84, 6.59, 5.48, 4.66, 3.97,
			3.21, 2.75, 2.18, 1.92, 1.56, 1.11
		]
	}`

	var data InputData
	json.Unmarshal([]byte(jsonData), &data)

	// 1. Inizializzazione della permutazione Poseidon2
	// t=2 (width), rf=8 (full rounds), rp=56 (partial rounds)
	p2Instance := poseidon2_bn254.NewPermutation(2, 8, 56)
	var scaledValues [MaxValues]int64
	var publicHashes [MaxValues]fr.Element // Array di hash al posto della Root

	// Supponiamo di caricare i dati JSON
	for i := 0; i < MaxValues; i++ {
		if i < len(data.Values) {
			scaledValues[i] = int64(math.Round(data.Values[i] * 1000))
		}

		var e fr.Element
		e.SetInt64(scaledValues[i])

		// Calcolo l'hash per ogni singolo valore
		state := []fr.Element{e, {}}
		p2Instance.Permutation(state)
		publicHashes[i] = state[0]
	}

	// Assignment
	var assignment QuantumValueCircuit
	var sum int64 = 0
	for i := 0; i < MaxValues; i++ {
		assignment.Values[i] = scaledValues[i]
		assignment.Hashes[i] = publicHashes[i] // Passiamo l'array
		sum += scaledValues[i]
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

	//exportForSnarkJS(proof, vk, publicWitness)
	// exportBinaryForRust(proof, vk, publicWitness)
	exportForSnark(proof, vk, publicWitness)
}

func exportForSnark(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness) {
	// 1. Estraiamo i valori dal Witness Pubblico
	// Gnark ordina alfabeticamente: [0] = ExpectedSum, [1] = Root
	pubVals := publicWitness.Vector().(fr.Vector)

	publicSignals := make([]string, len(pubVals))
	for i := range pubVals {
		publicSignals[i] = pubVals[i].String()
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
}

func exportBinaryForRust(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness) {

	fProof, _ := os.Create("proof.bin")
	proof.WriteTo(fProof)

	fVk, _ := os.Create("vk.bin")
	vk.WriteTo(fVk)

	fPub, _ := os.Create("public_witness.bin")
	publicWitness.WriteTo(fPub)

}
