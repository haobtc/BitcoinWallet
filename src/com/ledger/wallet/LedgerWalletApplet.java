/*
 *******************************************************************************
 *   Java Card Bitcoin Hardware Wallet
 *   (c) 2015 Ledger
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as
 *   published by the Free Software Foundation, either version 3 of the
 *   License, or (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *******************************************************************************
 */

/* This file is automatically processed from the .javap version and only included for convenience. Please refer to the .javap file
   for more readable code */

package com.ledger.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;

public class LedgerWalletApplet extends Applet {
    public LedgerWalletApplet(byte[] parameters, short parametersOffset, byte parametersLength) {
        Crypto.init();
        Bip32Cache.init();
        scratch256 = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        masterDerived = new byte[64];
        chipKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        trustedInputKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        developerKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        try {
            pairingKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        } catch (Exception e) {
        }
        reset();
        if (parametersLength != 0) {
            attestationPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
            attestationPublic = new byte[65];
            Secp256k1.setCommonCurveParameters(attestationPrivate);
            attestationPrivate.setS(parameters, parametersOffset, (short) 32);
            parametersOffset += (short) 32;
            attestationSignature = new byte[parameters[(short) (parametersOffset + 1)] + 2];
            Util.arrayCopy(parameters, parametersOffset, attestationSignature, (short) 0, (short) attestationSignature.length);
        }
    }

    private static void reset() {
        Crypto.random.generateData(scratch256, (short) 0, (short) 16);
        chipKey.setKey(scratch256, (short) 0);
        Util.arrayFillNonAtomic(scratch256, (short) 0, (short) 16, (byte) 0x00);
    }

    protected static boolean isContactless() {
        return ((APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A);
    }

    private static void signTransientPrivate(byte[] keyBuffer, short keyOffset, byte[] dataBuffer, short dataOffset, byte[] targetBuffer, short targetOffset) {
        Crypto.signTransientPrivate(keyBuffer, keyOffset, dataBuffer, dataOffset, targetBuffer, targetOffset);

    }

    private static void handleStorePublicKey(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        byte derivationSize = buffer[offset++];
        byte i;
        if (Crypto.keyAgreement == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (derivationSize > MAX_DERIVATION_PATH) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short) 0, DEFAULT_SEED_LENGTH, scratch256, (short) 0);
        i = Bip32Cache.copyPrivateBest(buffer, (short) (ISO7816.OFFSET_CDATA + 1), derivationSize, scratch256, (short) 0);
        for (; i < derivationSize; i++) {
            Util.arrayCopyNonAtomic(buffer, (short) (offset + 4 * i), scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short) 4);
            if (((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte) 0x80) == 0)) {
                if (!Bip32Cache.setPublicIndex(buffer, (short) (ISO7816.OFFSET_CDATA + 1), i)) {
                    ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
                }
            }
            if (!Bip32.derive(buffer)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Bip32Cache.storePrivate(buffer, (short) (ISO7816.OFFSET_CDATA + 1), (byte) (i + 1), scratch256);
        }
        offset += (short) (derivationSize * 4);
        Crypto.random.generateData(scratch256, (short) 32, (short) 32);
        signTransientPrivate(scratch256, (short) 0, scratch256, (short) 32, scratch256, (short) 64);
        if (Crypto.verifyPublic(buffer, offset, scratch256, (short) 32, scratch256, (short) 64)) {
            Bip32Cache.storePublic(buffer, (short) (ISO7816.OFFSET_CDATA + 1), derivationSize, buffer, offset);
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    private static void handleGetHalfPublicKey(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        if (!HAS_SETUP) {
            Crypto.random.generateData(scratch256, (short) 0, DEFAULT_SEED_LENGTH);
            Bip32.deriveSeed(DEFAULT_SEED_LENGTH);
            Crypto.initCipher(chipKey, true);
            Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short) 0, DEFAULT_SEED_LENGTH, masterDerived, (short) 0);
            HAS_SETUP = true;
        }
        byte derivationSize = buffer[offset++];
        byte i;
        if (Crypto.keyAgreement == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (derivationSize > MAX_DERIVATION_PATH) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short) 0, DEFAULT_SEED_LENGTH, scratch256, (short) 0);
        i = Bip32Cache.copyPrivateBest(buffer, (short) (ISO7816.OFFSET_CDATA + 1), derivationSize, scratch256, (short) 0);
        for (; i < derivationSize; i++) {
            Util.arrayCopyNonAtomic(buffer, (short) (offset + 4 * i), scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short) 4);
            if ((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte) 0x80) == 0) {
                if (!Bip32Cache.setPublicIndex(buffer, (short) (ISO7816.OFFSET_CDATA + 1), i)) {
                    ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
                }
            }
            if (!Bip32.derive(buffer)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Bip32Cache.storePrivate(buffer, (short) (ISO7816.OFFSET_CDATA + 1), (byte) (i + 1), scratch256);
        }
        Crypto.initTransientPrivate(scratch256, (short) 0);
        Crypto.keyAgreement.init(Crypto.transientPrivate);
        Crypto.keyAgreement.generateSecret(Secp256k1.SECP256K1_G, (short) 0, (short) Secp256k1.SECP256K1_G.length, scratch256, (short) 32);
        offset = 0;
        Crypto.random.generateData(buffer, offset, (short) 32);
        offset += 32;
        Util.arrayCopyNonAtomic(scratch256, (short) 32, buffer, offset, (short) 32);
        offset += 32;
        signTransientPrivate(scratch256, (short) 0, buffer, (short) 0, buffer, offset);
        offset += buffer[(short) (offset + 1)] + 2;
        Crypto.digestScratch.doFinal(buffer, (short) 0, (short) 32, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, offset);
    }

    private static void handleGetWalletPublicKey(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        byte derivationSize = buffer[offset++];
        byte i;
        if (derivationSize > MAX_DERIVATION_PATH) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short) 0, DEFAULT_SEED_LENGTH, scratch256, (short) 0);
        i = Bip32Cache.copyPrivateBest(buffer, (short) (ISO7816.OFFSET_CDATA + 1), derivationSize, scratch256, (short) 0);
        for (; i < derivationSize; i++) {
            Util.arrayCopyNonAtomic(buffer, (short) (offset + 4 * i), scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short) 4);
            if ((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte) 0x80) == 0) {
                if (!Bip32Cache.setPublicIndex(buffer, (short) (ISO7816.OFFSET_CDATA + 1), i)) {
                    ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
                }
            }
            if (!Bip32.derive(buffer)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Bip32Cache.storePrivate(buffer, (short) (ISO7816.OFFSET_CDATA + 1), (byte) (i + 1), scratch256);
        }

        if (!Bip32Cache.setPublicIndex(buffer, offset, derivationSize)) {
            ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
        }

        offset = 0;
        buffer[offset++] = (short) 65;
        Bip32Cache.copyLastPublic(buffer, offset);

        Util.arrayCopyNonAtomic(scratch256, (short) 32, buffer, (short) 200, (short) 32);
        Util.arrayCopyNonAtomic(buffer, offset, scratch256, (short) 0, (short) 65);
        offset += (short) 65;
        Util.arrayCopyNonAtomic(buffer, (short) 200, buffer, offset, (short) 32);
        offset += 32;
        apdu.setOutgoingAndSend((short) 0, offset);
    }

    private static void handleSetup(APDU apdu, boolean airgap) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        byte keyLength;
        keyLength = buffer[offset++];
        if (keyLength == 0) {
            keyLength = DEFAULT_SEED_LENGTH;
            Crypto.random.generateData(scratch256, (short) 0, keyLength);
            if (airgap) {
                Util.arrayCopyNonAtomic(scratch256, (short) 0, scratch256, (short) (256 - DEFAULT_SEED_LENGTH), DEFAULT_SEED_LENGTH);
            }
        } else {
            if ((keyLength < 0) || (keyLength > DEFAULT_SEED_LENGTH)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if (airgap) {
                Crypto.initCipherAES(pairingKey, false);
                Crypto.blobEncryptDecryptAES.doFinal(buffer, offset, keyLength, scratch256, (short) 0);
            } else {
                Util.arrayCopyNonAtomic(buffer, offset, scratch256, (short) 0, keyLength);
            }
        }
        Bip32.deriveSeed(keyLength);
        Crypto.initCipher(chipKey, true);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short) 0, DEFAULT_SEED_LENGTH, masterDerived, (short) 0);
        apdu.setOutgoingAndSend((short) 0, offset);
    }

    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        if (buffer[ISO7816.OFFSET_CLA] == CLA_BTC) {
            if (isContactless()) {
                APDU.waitExtension();
            }
            try {
                switch (buffer[ISO7816.OFFSET_INS]) {
                    case INS_SETUP:
                        handleSetup(apdu, false);
                        break;
                    case INS_GET_WALLET_PUBLIC_KEY:
                        handleGetWalletPublicKey(apdu);
                        break;
                    case INS_EXPORT_MASTER_DERIVED:
                        handlerExport(apdu);
                        break;
                    case INS_SIGN_HASH:
                        handleSign(apdu);
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
            } catch (Exception e) {
                if (e instanceof CardRuntimeException) {
                    throw ((CardRuntimeException) e);
                } else {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
            }

            return;
        } else if (buffer[ISO7816.OFFSET_CLA] == CLA_BTC_ADMIN) {
            try {
                switch (buffer[ISO7816.OFFSET_INS]) {
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
            } catch (Exception e) {
                if (e instanceof CardRuntimeException) {
                    throw ((CardRuntimeException) e);
                } else {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
            }
            return;
        } else if (buffer[ISO7816.OFFSET_CLA] == CLA_BTC_JC_EXTENSIONS) {
            try {
                switch (buffer[ISO7816.OFFSET_INS]) {
                    case INS_EXT_GET_HALF_PUBLIC_KEY:
                        handleGetHalfPublicKey(apdu);
                        break;
                    case INS_EXT_PUT_PUBLIC_KEY_CACHE:
                        handleStorePublicKey(apdu);
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
            } catch (Exception e) {
                if (e instanceof CardRuntimeException) {
                    throw ((CardRuntimeException) e);
                } else {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
            }
            return;
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    /***
     * export master privateKey and master chainCode
     * */
    private void handlerExport(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short) 0, DEFAULT_SEED_LENGTH, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, DEFAULT_SEED_LENGTH);
    }

    private void handleSign(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        byte derivationSize = buffer[offset++];
        byte i;
        if (Crypto.keyAgreement == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (derivationSize > MAX_DERIVATION_PATH) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short) 0, DEFAULT_SEED_LENGTH, scratch256, (short) 0);
        i = Bip32Cache.copyPrivateBest(buffer, (short) (ISO7816.OFFSET_CDATA + 1), derivationSize, scratch256, (short) 0);
        for (; i < derivationSize; i++) {
            Util.arrayCopyNonAtomic(buffer, (short) (offset + 4 * i), scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short) 4);
            if ((scratch256[Bip32.OFFSET_DERIVATION_INDEX] & (byte) 0x80) == 0) {
                if (!Bip32Cache.setPublicIndex(buffer, (short) (ISO7816.OFFSET_CDATA + 1), i)) {
                    ISOException.throwIt(SW_PUBLIC_POINT_NOT_AVAILABLE);
                }
            }
            if (!Bip32.derive(buffer)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Bip32Cache.storePrivate(buffer, (short) (ISO7816.OFFSET_CDATA + 1), (byte) (i + 1), scratch256);
        }
        offset += (short) (derivationSize * 4);
        Crypto.signTransientPreComputedHash(scratch256, (short) 0, buffer, offset, buffer, (short) 0);
        short signatureSize = (short) ((short) (buffer[1] & 0x00ff) + 2);
        apdu.setOutgoingAndSend((short) 0, signatureSize);
    }

    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
        short offset = bOffset;
        offset += (short) (bArray[offset] + 1);
        offset += (short) (bArray[offset] + 1);
        new LedgerWalletApplet(bArray, (short) (offset + 1), bArray[offset]).register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    protected static final short SW_PUBLIC_POINT_NOT_AVAILABLE = (short) 0x6FF6;
    private static final byte CLA_BTC_ADMIN = (byte) 0xD0;
    private static final byte CLA_BTC = (byte) 0x00;
    private static final byte CLA_BTC_JC_EXTENSIONS = (byte) 0x20;
    private static final byte INS_SETUP = (byte) 0x20;
    private static final byte INS_GET_WALLET_PUBLIC_KEY = (byte) 0x40;
    private static final byte INS_SIGN_HASH = (byte) 0x12;
    private static final byte INS_EXT_GET_HALF_PUBLIC_KEY = (byte) 0x20;
    private static final byte INS_EXT_PUT_PUBLIC_KEY_CACHE = (byte) 0x22;
    private static final byte DEFAULT_SEED_LENGTH = (byte) 64;
    private static final byte MAX_DERIVATION_PATH = (byte) 10;
    private static final byte INS_EXPORT_MASTER_DERIVED = (byte) 0x14;
    private static boolean HAS_SETUP = false;
    public static byte[] scratch256;
    protected static DESKey chipKey;
    protected static DESKey trustedInputKey;
    protected static DESKey developerKey;
    protected static byte[] masterDerived;
    protected static AESKey pairingKey;
    protected static ECPrivateKey attestationPrivate;
    protected static byte[] attestationPublic;
    protected static byte[] attestationSignature;
}
