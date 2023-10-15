from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import base64
import hashlib
import argparse
import os


def handle_blob(zip_name, crx_blob):
    publicKey, raw_crx_data = load_blob_in_viewer(zip_name, crx_blob)
    if publicKey == None:
        print('Public key not found, cannot generate "key" or extension ID.')
        exit(0)
    print('Public key (paste into manifest.json to preserve extention ID)')
    print('"key: "' + publicKey.decode('latin1') + '",')
    extensionId = publicKeyToExtensionId(publicKey)
    print('Calculated extension ID: ' + extensionId)


def load_blob_in_viewer(human_readable_name, crx_blob):
    print('Loading ' + human_readable_name)
    view = bytearray(crx_blob)

    # 50 4b 03 04
    if view[0] == 80 and view[1] == 75 and view[2] == 3 and view[3] == 4:
        print('Input is not a CRX file, but a ZIP file.')
        exit(0)

    # 43 72 32 34
    if view[0] != 67 or view[1] != 114 or view[2] != 50 or view[3] != 52:
        if isMaybeZipData(view):
            print('Input is not a CRX file, but possibly a ZIP file.')
        print('Invalid header: Does not start with Cr24')
        exit(0)

    # 02 00 00 00
    # 03 00 00 00 CRX3
    if view[4] != 2 and view[4] != 3 or view[5] or view[6] or view[7]:
        print('Unexpected crx format version number')
        exit(0)

    zipStartOffset, publicKeyBase64 = 0, ""

    if view[4] == 2:
        # CRX2
        publicKeyLength = calcLength(view[8], view[9], view[10], view[11])
        signatureLength = calcLength(view[12], view[13], view[14], view[15])
        zipStartOffset = 16 + publicKeyLength + signatureLength
        publicKeyBase64 = base64.b64encode(
            bytes(view[16:16 + publicKeyLength])).decode('utf-8')
    else:
        crx3HeaderLength = calcLength(view[8], view[9], view[10], view[11])
        zipStartOffset = 12 + crx3HeaderLength
        publicKeyBase64 = getPublicKeyFromProtoBuf(view, 12, zipStartOffset)

    # addons.opera.com creates CRX3 files by prepending the CRX3 header to the CRX2 data.
    if (
        view[4] == 3 and
        view[zipStartOffset] == 67 and
        view[zipStartOffset + 1] == 114 and
        view[zipStartOffset + 2] == 50 and
        view[zipStartOffset + 3] == 52
    ):
        print('Nested CRX: Expected zip data, but found another CRX file instead.')
        return load_blob_in_viewer(
            human_readable_name,
            crx_blob[zipStartOffset:]
        )

    zipFragment = bytes(crx_blob[zipStartOffset:])
    return publicKeyBase64, zipFragment


def calcLength(a, b, c, d):
    length = 0
    length += a << 0
    length += b << 8
    length += c << 16
    length += (d << 24) & 0xFFFFFFFF
    return length


def isMaybeZipData(view):
    for i in range(len(view) - 22, max(0, len(view) - 0xFFFF), -1):
        if view[i] == 0x50 and view[i + 1] == 0x4b and view[i + 2] == 0x05 and view[i + 3] == 0x06:
            return True
    return False


def getPublicKeyFromProtoBuf(bytesView, startOffset, endOffset):
    publicKeys = []
    crxIdBin = None
    while startOffset < endOffset:
        key, startOffset = getvarint(bytesView, startOffset)
        length, startOffset = getvarint(bytesView, startOffset)
        if key == 80002:
            sigdatakey, startOffset = getvarint(bytesView, startOffset)
            sigdatalen, startOffset = getvarint(bytesView, startOffset)
            if sigdatakey != 0xA:
                print(
                    'proto: Unexpected key in signed_header_data: {}'.format(sigdatakey))
            elif sigdatalen != 16:
                print(
                    'proto: Unexpected signed_header_data length {}'.format(sigdatalen))
            elif crxIdBin:
                print('proto: Unexpected duplicate signed_header_data')
            else:
                crxIdBin = bytesView[startOffset:startOffset + 16]
            startOffset += sigdatalen
            continue
        if key != 0x12:
            if key != 0x1a:
                print('proto: Unexpected key: {}'.format(key))
            startOffset += length
            continue
        keyproofend = startOffset + length
        keyproofkey, startOffset = getvarint(bytesView, startOffset)
        keyprooflength, startOffset = getvarint(bytesView, startOffset)
        if keyproofkey == 0x12:
            startOffset += keyprooflength
            if startOffset >= keyproofend:
                continue
            keyproofkey, startOffset = getvarint(bytesView, startOffset)
            keyprooflength, startOffset = getvarint(bytesView, startOffset)
        if keyproofkey != 0xA:
            startOffset += keyprooflength
            print('proto: Unexpected key in AsymmetricKeyProof: {}'.format(keyproofkey))
            continue
        if startOffset + keyprooflength > endOffset:
            print('proto: size of public_key field is too large')
            break
        publicKeys.append(getBinaryString(
            bytesView, startOffset, startOffset + keyprooflength))
        startOffset = keyproofend
    if not publicKeys:
        print('proto: Did not find any public key')
        return None
    if not crxIdBin:
        print('proto: Did not find crx_id')
        return None
    crxIdHex = binascii.hexlify(crxIdBin[:16]).decode('latin1')
    for publicKey in publicKeys:
        sha256sum = hashlib.sha256(publicKeys[0].encode('latin1')).hexdigest()
        if sha256sum[:32] == crxIdHex:
            return base64.b64encode(bytes(publicKey, 'latin1'))
    print('proto: None of the public keys matched with crx_id')
    return None


def getBinaryString(bytesView, startOffset, endOffset):
    binaryString = ''
    for i in range(startOffset, endOffset):
        binaryString += chr(bytesView[i])
    return binaryString


def getvarint(bytesView, startOffset):

    val = bytesView[startOffset] & 0x7F
    startOffset += 1
    if bytesView[startOffset - 1] < 0x80:
        return val, startOffset
    val |= (bytesView[startOffset] & 0x7F) << 7
    startOffset += 1
    if bytesView[startOffset - 1] < 0x80:
        return val, startOffset
    val |= (bytesView[startOffset] & 0x7F) << 14
    startOffset += 1
    if bytesView[startOffset - 1] < 0x80:
        return val, startOffset
    val |= (bytesView[startOffset] & 0x7F) << 21
    startOffset += 1
    if bytesView[startOffset - 1] < 0x80:
        return val, startOffset
    val = (val | (bytesView[startOffset] & 0xF) << 28) & 0xFFFFFFFF
    startOffset += 1
    if bytesView[startOffset - 1] & 0x80:
        print('proto: not a uint32')
    return val, startOffset


def publicKeyToExtensionId(base64encodedKey):
    key = base64.b64decode(base64encodedKey).decode('latin1')
    sha256sum = hashlib.sha256(key.encode('latin1')).hexdigest()
    extensionId = ''
    ord_a = ord('a')
    for i in range(32):
        extensionId += chr(int(sha256sum[i], 16) + ord_a)
    return extensionId


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Process a file")
    parser.add_argument("filename", help="The name of the file to process")
    args = parser.parse_args()
    filename = args.filename

    if not os.path.exists(filename):
        print(f"Error: The file '{filename}' dose not exist.")
        exit(0)

    # The main code
    try:
        with open(filename, 'rb') as file:
            content = file.read()
            handle_blob(filename, content)
    except Exception as e:
        print(
            f"Error: An error occurred while processing the file '{filename}': {str(e)}")
