package main

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnark_mimc "github.com/consensys/gnark/std/hash/mimc"
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
		// Calcolo hash foglia
		var e fr.Element
		e.SetInt64(scaledValues[idxValue])
		hFunc.Reset()
		hFunc.Write(e.Marshal())
		leaves = append(leaves, hFunc.Sum(nil))
	}

	// Costruiamo i livelli dell'albero
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

	// Preparazione Witness
	var assignment QuantumValueCircuit
	assignment.Root = root
	var sum int64 = 0

	for i := 0; i < MaxValues; i++ {
		assignment.Values[i] = scaledValues[i]
		sum += scaledValues[i]

		// Generazione Path per la foglia i
		currIdx := i
		for d := 0; d < TreeDepth; d++ {
			if currIdx%2 == 0 {
				// path a destra
				assignment.Paths[i][d] = tree[d][currIdx+1]
				assignment.IsRight[i][d] = 1
			} else {
				// path a sinistra
				assignment.Paths[i][d] = tree[d][currIdx-1]
				assignment.IsRight[i][d] = 0
			}
			currIdx /= 2
		}
	}
	assignment.ExpectedSum = sum

	// prova withness
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Printf("Errore: %v\n", err)
		return
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err == nil {
		fmt.Printf("Somma verificata: %d su %d slot.\n", sum, MaxValues)
	}
}
