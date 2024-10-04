const express = require('express');
const router = express.Router();
const crypto = require('crypto'); // Para SHA-1
const gostCrypto = require('gost-crypto');

// ------------------- SHA-1 (Cifrado, Solo Hashing) -------------------
router.post('/sha1', (req, res) => {
  const { data } = req.body;  // Campo necesario: 'data' (mensaje)

  if (!data) {
    return res.status(400).json({ error: 'Se requiere un mensaje para cifrar' });
  }

  // Cifrado con SHA-1 (no reversible)
  const hash = crypto.createHash('sha1').update(data).digest('hex');
  res.json({ encryptedData: hash });
});

// ------------------- GOST (Cifrado y Descifrado Simétrico) -------------------
// Ruta para cifrar usando GOST
router.post('/gost/encrypt', (req, res) => {
    const { data, key } = req.body;
  
    if (!data || !key) {
      return res.status(400).json({ error: 'Se requieren un mensaje y una clave para cifrar' });
    }
  
    try {
      // Asegúrate de que estés usando correctamente la librería de GOST
      const cipher = new gostCrypto.cipher.GostCipher();
      const encryptedData = cipher.process(data); // Aquí verifica si 'process' requiere algún ajuste
  
      // Enviar el resultado cifrado
      res.json({ encryptedData });
    } catch (error) {
      console.error('Error al cifrar con GOST:', error);
      res.status(500).json({ error: 'Error al cifrar con GOST' });
    }
  });
  

// ------------------- LUC (Cifrado y Descifrado Asimétrico) -------------------
router.post('/luc/encrypt', (req, res) => {
  const { data, key } = req.body;  // Campos necesarios: 'data' (mensaje), 'key' (clave)

  if (!data || !key) {
    return res.status(400).json({ error: 'Se requieren un mensaje y una clave para cifrar' });
  }

  // Ejemplo de cifrado con LUC (basado en la secuencia de Lucas)
  const lucasKey = (n) => {
    let L = [2, 1];
    for (let i = 2; i <= n; i++) {
      L.push(L[i-1] + L[i-2]);
    }
    return L[n];
  };

  const encryptedData = lucasKey(data.length + key.length);  // Lógica simplificada
  res.json({ encryptedData });
});

router.post('/luc/decrypt', (req, res) => {
  const { data, key } = req.body;  // Campos necesarios: 'data' (mensaje cifrado), 'key' (clave)

  if (!data || !key) {
    return res.status(400).json({ error: 'Se requieren un mensaje cifrado y una clave para descifrar' });
  }

  // Ejemplo de descifrado de LUC (puedes adaptar esta lógica según el cifrado real)
  const lucasKey = (n) => {
    let L = [2, 1];
    for (let i = 2; i <= n; i++) {
      L.push(L[i-1] + L[i-2]);
    }
    return L[n];
  };

  const decryptedData = lucasKey(data.length - key.length);  // Lógica simplificada
  res.json({ decryptedData });
});

module.exports = router;
