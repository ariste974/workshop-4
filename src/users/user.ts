import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { createRandomSymmetricKey, exportSymKey, rsaEncrypt, symEncrypt } from "../crypto";
import { GetNodeRegistryBody, Node } from "../registry/registry";

/**
 * Type définissant le format des messages envoyés
 */
export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

/**
 * Crée et démarre un serveur pour simuler un utilisateur du réseau Onion
 * @param userId - L'identifiant unique de l'utilisateur
 * @returns Le serveur HTTP créé
 */
export async function user(userId: number) {
  // Initialisation de l'application Express
  const userApp = express();
  userApp.use(express.json());
  userApp.use(bodyParser.json());

  // Variables pour stocker l'état des messages
  let dernierMessageReçu: string | null = null;
  let dernierMessageEnvoyé: string | null = null;
  let dernierCircuit: number[] = [];

  // Endpoint pour vérifier que le serveur est en marche
  userApp.get("/status", (req, res) => res.send("live"));

  /**
   * Endpoint pour recevoir un message
   * Cette route est appelée par le dernier nœud du circuit Onion
   */
  userApp.post("/message", (req, res) => {
    const { message } = req.body;
    dernierMessageReçu = message;
    res.status(200).send("success");
  });

  // Endpoints pour récupérer l'état des messages et du circuit
  userApp.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: dernierMessageReçu });
  });

  userApp.get("/getLastSentMessage", (req, res) => {
    res.json({ result: dernierMessageEnvoyé });
  });

  userApp.get("/getLastCircuit", (req, res) => {
    res.json({ result: dernierCircuit });
  });

  /**
   * Endpoint principal pour envoyer un message via le réseau Onion
   * Implémente le chiffrement en couches caractéristique des réseaux Onion
   */
  userApp.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;
    dernierMessageEnvoyé = message;
  
    try {
      // Récupération de la liste des nœuds disponibles depuis le registre
      const response = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const { nodes } = await response.json() as GetNodeRegistryBody;
      
      // Sélection aléatoire de 3 nœuds pour former le circuit Onion
      const circuit = sélectionnerNœudsAléatoires(nodes, 3);
      dernierCircuit = circuit.map(node => node.nodeId);
      const [nœudEntrée, nœudIntermédiaire, nœudSortie] = circuit;
  
      // Création des clés de chiffrement pour chaque couche
      const cléEntrée = await createRandomSymmetricKey();
      const cléIntermédiaire = await createRandomSymmetricKey();
      const cléSortie = await createRandomSymmetricKey();
  
      // Construction du message en couches, de l'intérieur vers l'extérieur
      let données = message;
      
      // Couche 3 (sortie) - Chiffrement du message pour le nœud de sortie
      const destinationFinale = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");
      let couche = destinationFinale + données;
      let coucheCryptée = await symEncrypt(cléSortie, couche);
      let cléCryptée = await rsaEncrypt(await exportSymKey(cléSortie), nœudSortie.pubKey);
      données = cléCryptée + coucheCryptée;
  
      // Couche 2 (intermédiaire) - Préparation du message pour le nœud intermédiaire
      const destinationIntermédiaire = `${BASE_ONION_ROUTER_PORT + nœudSortie.nodeId}`.padStart(10, "0");
      couche = destinationIntermédiaire + données;
      coucheCryptée = await symEncrypt(cléIntermédiaire, couche);
      cléCryptée = await rsaEncrypt(await exportSymKey(cléIntermédiaire), nœudIntermédiaire.pubKey);
      données = cléCryptée + coucheCryptée;
  
      // Couche 1 (entrée) - Préparation du message pour le nœud d'entrée
      const destinationEntrée = `${BASE_ONION_ROUTER_PORT + nœudIntermédiaire.nodeId}`.padStart(10, "0");
      couche = destinationEntrée + données;
      coucheCryptée = await symEncrypt(cléEntrée, couche);
      cléCryptée = await rsaEncrypt(await exportSymKey(cléEntrée), nœudEntrée.pubKey);
      données = cléCryptée + coucheCryptée;
  
      // Envoi du message chiffré au premier nœud (entrée) du circuit
      await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + nœudEntrée.nodeId}/message`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: données }),
      });
  
      res.status(200).json({ success: true });
    } catch (error) {
      console.error("Erreur lors de l'envoi du message:", error);
      res.status(500).json({ error: "Échec de l'envoi du message" });
    }
  });
  
  /**
   * Fonction utilitaire pour sélectionner des nœuds aléatoires du réseau
   * @param nodes - Liste de tous les nœuds disponibles
   * @param count - Nombre de nœuds à sélectionner
   * @returns Un tableau des nœuds sélectionnés aléatoirement
   */
  function sélectionnerNœudsAléatoires(nodes: Node[], count: number): Node[] {
    const mélangés = [...nodes];
    // Algorithme de Fisher-Yates pour mélanger le tableau
    for (let i = mélangés.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [mélangés[i], mélangés[j]] = [mélangés[j], mélangés[i]];
    }
    return mélangés.slice(0, count);
  }

  // Démarrage du serveur
  const server = userApp.listen(BASE_USER_PORT + userId, () => {
    console.log(`Utilisateur ${userId} à l'écoute sur le port ${BASE_USER_PORT + userId}`);
  });

  return server;
}