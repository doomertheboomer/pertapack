const fs = require('fs');
const crypto = require('crypto');
const crc32 = require('crc').crc32;

if (process.argv.length !== 3) {
    console.error(`Usage: ${process.argv[1]} <file_to_encrypt>`);
    process.exit(1);
}

const inputFilename = process.argv[2];
const outputFilename = inputFilename;
const originalFilename = `${inputFilename}.orig`;

function renameFile(oldPath, newPath) {
    return new Promise((resolve, reject) => {
        fs.rename(oldPath, newPath, (err) => {
            if (err) reject(err);
            else resolve();
        });
    });
}

function readFile(filePath) {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, (err, data) => {
            if (err) reject(err);
            else resolve(data);
        });
    });
}

function writeFile(filePath, data) {
    return new Promise((resolve, reject) => {
        fs.writeFile(filePath, data, (err) => {
            if (err) reject(err);
            else resolve();
        });
    });
}

function encryptAES(plaintext, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(plaintext);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted;
}

(async () => {
    try {
        await renameFile(inputFilename, originalFilename);
        const plaintext = await readFile(originalFilename);
        const key = Buffer.from('01234567890123456789012345678901', 'utf-8');
        const iv = Buffer.from('xxxxPERTAPCKxxxx', 'utf-8');
        const ciphertext = encryptAES(plaintext, key, iv);

        const crc = crc32(plaintext).readUInt32LE(0);
        const header = Buffer.alloc(13);
        header.write('PTPCK', 0, 5, 'utf-8');
        header.writeUInt32LE(crc, 5);
        header.writeUInt32LE(plaintext.length, 9);
		
        const outputFile = Buffer.concat([header, ciphertext]);
        await writeFile(outputFilename, outputFile);

        console.log('File encrypted successfully!');
    } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
    }
})();
