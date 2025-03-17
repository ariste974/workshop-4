import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import crypto from "crypto";
import http from "http";
import { rsaDecrypt, importSymKey, symDecrypt, importPrvKey } from "../crypto";

/**
 * Crée et démarre un serveur pour simuler un routeur Onion
 * @param nodeId - L'identifiant unique du nœud
 * @returns Le serveur HTTP créé
 */
export async function simpleOnionRouter(nodeId: number) {
  // Initialisation de l'application Express
  const routeurOnion = express();
  routeurOnion.use(express.json());
  routeurOnion.use(bodyParser.json());

  // Variables pour stocker l'état des messages
  let dernierMessageChiffréReçu: string | null = null;
  let dernierMessageDéchiffréReçu: string | null = null;
  let dernièreDestinationMessage: number | null = null;

  // Génération des paires de clés RSA pour le chiffrement asymétrique
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  // Conversion des clés au format Base64 pour faciliter leur transmission
  const cléPubliqueDer = publicKey.export({ type: "spki", format: "der" });
  const cléPubliqueBase64 = Buffer.from(cléPubliqueDer).toString("base64");
  const cléPrivéeDer = privateKey.export({ type: "pkcs8", format: "der" });
  const cléPrivéeBase64 = Buffer.from(cléPrivéeDer).toString("base64");
  const cléPrivéeCrypto = await importPrvKey(cléPrivéeBase64);

  // Enregistrement du nœud auprès du registre central
  const donnéesEnregistrement = JSON.stringify({ nodeId, pubKey: cléPubliqueBase64 });
  const requête = http.request({
    hostname: 'localhost',
    port: REGISTRY_PORT,
    path: '/registerNode',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(donnéesEnregistrement),
    },
  });
  
  requête.on('error', (err) => console.error("Erreur d'enregistrement:", err));
  requête.write(donnéesEnregistrement);
  requête.end();

  // Endpoint pour vérifier que le serveur est en marche
  routeurOnion.get("/status", (req, res) => res.send("live"));

  // Endpoints pour récupérer l'état des messages
  routeurOnion.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: dernierMessageChiffréReçu });
  });

  routeurOnion.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: dernierMessageDéchiffréReçu });
  });

  routeurOnion.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: dernièreDestinationMessage });
  });

  routeurOnion.get("/getPrivateKey", (req, res) => {
    res.json({ result: cléPrivéeBase64 });
  });

  /**
   * Endpoint principal pour recevoir et traiter un message chiffré
   * Permet de décrypter une couche du message Onion et de le transmettre au prochain nœud
   */
  routeurOnion.post("/message", async (req, res) => {
    try {
      const { message } = req.body;
      dernierMessageChiffréReçu = message;

      // Séparation de la clé chiffrée et du contenu chiffré
      // La clé RSA chiffrée fait exactement 344 caractères en base64
      const cléChiffrée = message.substring(0, 344);
      const contenuChiffré = message.substring(344);

      // Déchiffrement de la clé symétrique avec la clé privée RSA du nœud
      const cléSymétriqueBase64 = await rsaDecrypt(cléChiffrée, cléPrivéeCrypto);
      const cléSymétrique = await importSymKey(cléSymétriqueBase64);

      // Déchiffrement du contenu avec la clé symétrique obtenue
      const contenuDéchiffré = await symDecrypt(cléSymétriqueBase64, contenuChiffré);
      
      // Extraction de l'adresse de destination (10 premiers caractères)
      const destinationSuivante = parseInt(contenuDéchiffré.substring(0, 10), 10);
      const messageSuivant = contenuDéchiffré.substring(10);

      // Mise à jour des variables d'état
      dernierMessageDéchiffréReçu = messageSuivant;
      dernièreDestinationMessage = destinationSuivante;

      // Transmission du message au prochain nœud ou à l'utilisateur final
      await fetch(`http://localhost:${destinationSuivante}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: messageSuivant }),
      });

      res.status(200).send("success");
    } catch (error) {
      console.error("Erreur de traitement du nœud:", error);
      res.status(500).send("error");
    }
  });

  // Démarrage du serveur
  const server = routeurOnion.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Routeur Onion ${nodeId} à l'écoute sur le port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}