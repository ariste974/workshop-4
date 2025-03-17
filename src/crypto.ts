import { webcrypto } from "crypto";

/**
 * Module de cryptographie
 * Fournit des fonctions pour le chiffrement/déchiffrement RSA et AES
 * Utilisé pour la communication sécurisée dans le réseau Onion
 */

// #########################
// ### Fonctions utilitaires ###
// #########################

/**
 * Convertit un ArrayBuffer en chaîne Base64
 * @param buffer - Données binaires à convertir
 * @return Chaîne encodée en Base64
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

/**
 * Convertit une chaîne Base64 en ArrayBuffer
 * @param base64 - Chaîne Base64 à convertir
 * @return Données binaires issues du décodage
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var tampon = Buffer.from(base64, "base64");
  return tampon.buffer.slice(tampon.byteOffset, tampon.byteOffset + tampon.byteLength);
}

// ############################
// ### Clés RSA (asymétriques) ###
// ############################

/**
 * Type représentant une paire de clés RSA
 */
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;  // Clé publique pour chiffrer
  privateKey: webcrypto.CryptoKey; // Clé privée pour déchiffrer
};

/**
 * Génère une nouvelle paire de clés RSA
 * @return Paire de clés publique/privée
 */
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const paireDeClés = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",         // Algorithme avec padding OAEP
      modulusLength: 2048,      // Longueur de clé de 2048 bits (sécurité standard)
      publicExponent: new Uint8Array([1, 0, 1]), // Exposant public standard (65537)
      hash: "SHA-256",          // Fonction de hachage utilisée
    },
    true,                       // Les clés sont exportables
    ["encrypt", "decrypt"]      // Opérations autorisées
  );

  return {
    publicKey: paireDeClés.publicKey,
    privateKey: paireDeClés.privateKey,
  };
}

/**
 * Exporte une clé publique au format Base64
 * @param clé - Clé publique à exporter
 * @return Représentation Base64 de la clé publique
 */
export async function exportPubKey(clé: webcrypto.CryptoKey): Promise<string> {
  const cléExportée = await webcrypto.subtle.exportKey("spki", clé);
  return arrayBufferToBase64(cléExportée);
}

/**
 * Exporte une clé privée au format Base64
 * @param clé - Clé privée à exporter (peut être null)
 * @return Représentation Base64 de la clé privée ou null
 */
export async function exportPrvKey(
  clé: webcrypto.CryptoKey | null
): Promise<string | null> {
  if (!clé) return null;
  const cléExportée = await webcrypto.subtle.exportKey("pkcs8", clé);
  return arrayBufferToBase64(cléExportée);
}

/**
 * Importe une clé publique depuis sa représentation Base64
 * @param chaîneDeLaClé - Représentation Base64 de la clé
 * @return Objet CryptoKey utilisable pour le chiffrement
 */
export async function importPubKey(
  chaîneDeLaClé: string
): Promise<webcrypto.CryptoKey> {
  const tamponBinaire = base64ToArrayBuffer(chaîneDeLaClé);
  return webcrypto.subtle.importKey(
    "spki",                  // Format standard pour les clés publiques
    tamponBinaire,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,                    // La clé est exportable
    ["encrypt"]              // Opération autorisée : chiffrement uniquement
  );
}

/**
 * Importe une clé privée depuis sa représentation Base64
 * @param chaîneDeLaClé - Représentation Base64 de la clé
 * @return Objet CryptoKey utilisable pour le déchiffrement
 */
export async function importPrvKey(
  chaîneDeLaClé: string
): Promise<webcrypto.CryptoKey> {
  const tamponBinaire = base64ToArrayBuffer(chaîneDeLaClé);
  return webcrypto.subtle.importKey(
    "pkcs8",                 // Format standard pour les clés privées
    tamponBinaire,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,                    // La clé est exportable
    ["decrypt"]              // Opération autorisée : déchiffrement uniquement
  );
}

/**
 * Chiffre un message avec une clé publique RSA
 * @param donnéesBase64 - Données à chiffrer (en Base64)
 * @param chaîneCléPublique - Clé publique en format Base64
 * @return Données chiffrées en Base64
 */
export async function rsaEncrypt(
  donnéesBase64: string,
  chaîneCléPublique: string
): Promise<string> {
  // Importe la clé publique depuis sa représentation Base64
  const cléPublique = await importPubKey(chaîneCléPublique);
  
  // Encode les données en binaire
  const données = new TextEncoder().encode(donnéesBase64).buffer;
  
  // Chiffre les données avec la clé publique
  const donnéesChiffrées = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    cléPublique,
    données
  );
  
  // Retourne les données chiffrées en Base64
  return arrayBufferToBase64(donnéesChiffrées);
}

/**
 * Déchiffre un message avec une clé privée RSA
 * @param données - Données chiffrées en Base64
 * @param cléPrivée - Clé privée pour le déchiffrement
 * @return Données déchiffrées sous forme de chaîne
 */
export async function rsaDecrypt(
  données: string,
  cléPrivée: webcrypto.CryptoKey
): Promise<string> {
  // Convertit les données Base64 en binaire
  const donnéesChiffrées = base64ToArrayBuffer(données);
  
  // Déchiffre les données avec la clé privée
  const donnéesDéchiffrées = await webcrypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    cléPrivée,
    donnéesChiffrées
  );
  
  // Convertit le résultat binaire en chaîne de caractères
  return new TextDecoder().decode(donnéesDéchiffrées);
}

// ############################
// ### Clés symétriques (AES) ###
// ############################

/**
 * Génère une clé symétrique AES-CBC aléatoire
 * @return Nouvelle clé symétrique
 */
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  return webcrypto.subtle.generateKey(
    {
      name: "AES-CBC",      // Algorithme AES en mode CBC
      length: 256,          // Longueur de clé 256 bits (sécurité élevée)
    },
    true,                   // La clé est exportable
    ["encrypt", "decrypt"]  // Opérations autorisées
  );
}

/**
 * Exporte une clé symétrique au format Base64
 * @param clé - Clé symétrique à exporter
 * @return Représentation Base64 de la clé
 */
export async function exportSymKey(clé: webcrypto.CryptoKey): Promise<string> {
  const cléExportée = await webcrypto.subtle.exportKey("raw", clé);
  return arrayBufferToBase64(cléExportée);
}

/**
 * Importe une clé symétrique depuis sa représentation Base64
 * @param chaîneDeLaClé - Représentation Base64 de la clé
 * @return Objet CryptoKey utilisable pour le chiffrement/déchiffrement
 */
export async function importSymKey(
  chaîneDeLaClé: string
): Promise<webcrypto.CryptoKey> {
  const tamponBinaire = base64ToArrayBuffer(chaîneDeLaClé);
  return webcrypto.subtle.importKey(
    "raw",                  // Format brut pour les clés symétriques
    tamponBinaire,
    {
      name: "AES-CBC",
    },
    true,                   // La clé est exportable
    ["encrypt", "decrypt"]  // Opérations autorisées
  );
}

/**
 * Chiffre un message avec une clé symétrique AES
 * @param clé - Clé symétrique pour le chiffrement
 * @param données - Données à chiffrer
 * @return Données chiffrées en Base64 (inclut le vecteur d'initialisation)
 */
export async function symEncrypt(
  clé: webcrypto.CryptoKey,
  données: string
): Promise<string> {
  // Génère un vecteur d'initialisation (IV) aléatoire de 16 octets
  const vecteurInitialisation = webcrypto.getRandomValues(new Uint8Array(16));
  
  // Encode les données en binaire
  const donnéesEncodées = new TextEncoder().encode(données).buffer;
  
  // Chiffre les données avec la clé et le vecteur d'initialisation
  const donnéesChiffrées = await webcrypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv: vecteurInitialisation,  // Vecteur d'initialisation unique pour chaque message
    },
    clé,
    donnéesEncodées
  );
  
  // Combine le vecteur d'initialisation et les données chiffrées
  // Le vecteur doit être inclus pour permettre le déchiffrement
  const combiné = new Uint8Array(vecteurInitialisation.length + donnéesChiffrées.byteLength);
  combiné.set(new Uint8Array(vecteurInitialisation), 0);
  combiné.set(new Uint8Array(donnéesChiffrées), vecteurInitialisation.length);
  
  // Retourne le tout en Base64
  return arrayBufferToBase64(combiné.buffer);
}

/**
 * Déchiffre un message avec une clé symétrique AES
 * @param chaîneDeLaClé - Clé symétrique en format Base64
 * @param donnéesChiffrées - Données chiffrées en Base64 (avec vecteur d'initialisation)
 * @return Données déchiffrées sous forme de chaîne
 */
export async function symDecrypt(
  chaîneDeLaClé: string,
  donnéesChiffrées: string
): Promise<string> {
  // Importe la clé depuis sa représentation Base64
  const clé = await importSymKey(chaîneDeLaClé);
  
  // Convertit les données Base64 en binaire
  const tamponBinaire = base64ToArrayBuffer(donnéesChiffrées);
  
  // Extrait le vecteur d'initialisation (16 premiers octets)
  const vecteurInitialisation = tamponBinaire.slice(0, 16);
  
  // Extrait les données chiffrées (le reste)
  const données = tamponBinaire.slice(16);
  
  // Déchiffre les données avec la clé et le vecteur d'initialisation
  const donnéesDéchiffrées = await webcrypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: vecteurInitialisation,
    },
    clé,
    données
  );
  
  // Convertit le résultat binaire en chaîne de caractères
  return new TextDecoder().decode(donnéesDéchiffrées);
}