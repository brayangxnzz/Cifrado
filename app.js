const express = require('express');
const gostCrypto = require('gost-crypto');

const app = express();
app.use(express.json());

// Ruta para cifrar usando GOST
app.post('/gost/encrypt', (req, res) => {
  const { data, key } = req.body;

  if (!data || !key) {
    return res.status(400).json({ error: 'Se requieren un mensaje y una clave para cifrar' });
  }

  try {
    const alg = {
      name: 'GOST 28147',
      version: 1989,
      mode: 'CFB',
      length: 64,
    };

    const cipher = gostCrypto.cipher(alg);
    const keyData = gostCrypto.coding.Hex.decode(key);

    cipher.init({ key: keyData });

    const encodedMessage = gostCrypto.coding.Utf8.encode(data);
    const encryptedData = cipher.process(encodedMessage);

    res.json({ encryptedData: gostCrypto.coding.Hex.encode(encryptedData) });
  } catch (error) {
    console.error('Error al cifrar con GOST:', error);
    res.status(500).json({ error: 'Error al cifrar con GOST' });
  }
});

// Ruta para descifrar usando GOST
app.post('/gost/decrypt', (req, res) => {
  const { data, key } = req.body;

  if (!data || !key) {
    return res.status(400).json({ error: 'Se requieren un mensaje cifrado y una clave para descifrar' });
  }

  try {
    const alg = {
      name: 'GOST 28147',
      version: 1989,
      mode: 'CFB',
      length: 64,
    };

    const cipher = gostCrypto.cipher(alg);
    const keyData = gostCrypto.coding.Hex.decode(key);

    cipher.init({ key: keyData });

    const encryptedData = gostCrypto.coding.Hex.decode(data);
    const decryptedData = cipher.process(encryptedData);

    res.json({ decryptedData: gostCrypto.coding.Utf8.decode(decryptedData) });
  } catch (error) {
    console.error('Error al descifrar con GOST:', error);
    res.status(500).json({ error: 'Error al descifrar con GOST' });
  }
});

const port = 3000;
app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
