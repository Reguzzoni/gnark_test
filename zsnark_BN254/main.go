package main

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const MaxsInputValues = 100

type InputData struct {
	Values []float64 `json:"values"`
}

// custom circuit ZK per somma dinamica di valori, per esempio 100!
type DynamicSumCircuit struct {
	Inputs [MaxsInputValues]frontend.Variable `gnark:",secret"`

	ExpectedSum frontend.Variable `gnark:",public"`
}

func (c *DynamicSumCircuit) Define(api frontend.API) error {
	var sum frontend.Variable = 0
	for idx := 0; idx < MaxsInputValues; idx++ {
		sum = api.Add(sum, c.Inputs[idx])
	}

	//fmt.Println("sum - expectedSum:", sum, c.ExpectedSum)
	api.AssertIsEqual(sum, c.ExpectedSum)
	return nil
}

func main() {

	var myCircuit DynamicSumCircuit
	// cyrve BN254 (Groth16), funziona ma non è quantum safe mmm
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		panic(err)
	}

	// gestioni chiavi
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	// json esempio
	jsonData := `{"values": [1.3, 2.3, 4.234]}`
	var data InputData
	json.Unmarshal([]byte(jsonData), &data)

	// Withness con scaling a 1000 (valori con 3 cifre decimali per esempio, TODO riadattare)
	var assignment DynamicSumCircuit
	var currentSum int64 = 0
	scale := 1000.0

	for i := 0; i < MaxsInputValues; i++ {
		if i < len(data.Values) {
			// scaling value
			scaledVal := int64(math.Round(data.Values[i] * scale))
			assignment.Inputs[i] = scaledVal
			currentSum += scaledVal
		} else {
			// Padding: riempiamo i posti vuoti con 0
			assignment.Inputs[i] = 0
		}
	}
	assignment.ExpectedSum = currentSum

	// Creiamo la witness (testimone)
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// Generazione prova ZK
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("err: %v\n", err)
	} else {
		fmt.Println("Success")
	}

	// test controprova
	badAssignment := DynamicSumCircuit{
		ExpectedSum: 9999, // valore a caso errato
	}
	badPublicWitness, _ := frontend.NewWitness(&badAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	err = groth16.Verify(proof, vk, badPublicWitness)
	if err != nil {
		fmt.Println("Success test con errore")
	}
}
