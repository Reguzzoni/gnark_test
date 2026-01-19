package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// --- ZKP: Prova che la somma degli elementi non superi un limite ---
type SumCheckCircuit struct {
	Inputs []frontend.Variable `gnark:",secret"`
	Sum    frontend.Variable   `gnark:",public"`
}

func (c *SumCheckCircuit) Define(api frontend.API) error {
	var res frontend.Variable = 0
	for _, v := range c.Inputs {
		res = api.Add(res, v)
	}
	api.AssertIsEqual(res, c.Sum)
	return nil
}

func main() {
	// 1. SIMULAZIONE INPUT DA JSON (100 Valori KPI)
	kpiValues := make([]uint64, 100)
	var expectedSum uint64
	for i := 0; i < 100; i++ {
		kpiValues[i] = uint64(i + 1) // Valori da 1 a 100
		expectedSum += kpiValues[i]
	}

	// 2. SETUP LATTIGO (BFV)
	params, _ := bfv.NewParametersFromLiteral(bfv.PN15QP880)
	kgen := bfv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()

	// Ci serve la Rotation Key per sommare gli slot tra loro
	galEls := params.GaloisElementsForColumnRotation()
	gks := kgen.GenGaloisKeys(galEls, sk)

	encryptor := bfv.NewEncryptor(params, pk)
	encoder := bfv.NewEncoder(params)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{GalEls: galEls, Gks: gks})

	// 3. COMMITMENT (Batching di 100 valori in 1 Ciphertext)
	slots := make([]uint64, params.N())
	copy(slots, kpiValues)

	pt := bfv.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(slots, pt)
	ct := encryptor.EncryptNew(pt)
	fmt.Printf("[Client] Committati %d valori in un singolo Ciphertext\n", len(kpiValues))

	// 4. CALCOLO OMOMORFICO (Sommatoria interna tramite rotazioni)
	// Questa è la tecnica "Full Sum" per sommare tutti gli slot tra loro
	for i := 1; i < params.N(); i <<= 1 {
		rotated := evaluator.RotateRowsNew(ct)
		evaluator.Add(ct, rotated, ct)
	}
	fmt.Println("[Server] Sommatoria omomorfica completata (Log2 n rotazioni)")

	// 5. ZKP (Gnark) - Prova di coerenza
	fmt.Println("[Client] Generazione prova ZK per la sommatoria...")
	circuit := &SumCheckCircuit{Inputs: make([]frontend.Variable, 100)}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	pkZK, vkZK, _ := groth16.Setup(ccs)

	assignment := &SumCheckCircuit{Sum: expectedSum}
	for i := 0; i < 100; i++ {
		assignment.Inputs[i] = kpiValues[i]
	}

	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	pubWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, pkZK, witness)

	// 6. VERIFICA E DECRYPT
	if err := groth16.Verify(proof, vkZK, pubWitness); err == nil {
		fmt.Println("[Auditor] ✓ Prova ZK valida: la somma corrisponde ai dati di dettaglio.")
	}

	decryptor := bfv.NewDecryptor(params, sk)
	resPt := decryptor.DecryptNew(ct)
	resSlots := make([]uint64, params.N())
	encoder.Decode(resPt, resSlots)

	fmt.Printf("\n[Risultato Finale] Sommatoria KPI Decifrata: %d (Attesa: %d)\n", resSlots[0], expectedSum)
}
