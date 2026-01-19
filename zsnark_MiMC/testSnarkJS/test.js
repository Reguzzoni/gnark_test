import { groth16 } from "snarkjs";
import fs from "fs";

async function run() {
  try {
    const proof = JSON.parse(fs.readFileSync("./proof.json"));
    const publicSignals = JSON.parse(fs.readFileSync("./public.json"));
    const vKey = JSON.parse(fs.readFileSync("./verification_key.json"));

    console.log(" caricati.");
    console.log("prof :", proof);
    console.log("pubs :", publicSignals);
    console.log("vKey :", vKey);

    console.log(" SnarkJS prova");

    const res = await groth16.verify(vKey, publicSignals, proof);

    if (res === true) {
      console.log("VERIFICA fatta");
    } else {
      console.log("Errore verifica");
    }
  } catch (err) {
    console.error("Errore durante la verifica:", err);
  }
}

run();
