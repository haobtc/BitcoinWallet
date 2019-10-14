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

package com.bixin.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.PINException;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;

public class BiXinWalletApplet extends Applet {

    private static final byte CLA_BTC = (byte) 0x00;
    private static final byte INS_SETUP = (byte) 0x08;
    private static final byte INS_SIGN_HASH = (byte) 0x12;
    private static final byte INS_EXT_GET_EXTENDED_PUBLIC_KEY = (byte) 0x10;
    private static final byte DEFAULT_SEED_LENGTH = (byte) 64;
    private static final byte MAX_DERIVATION_PATH = (byte) 10;
    private static final byte INS_EXPORT_MASTER_DERIVED = (byte) 0x14;
    private static final byte INS_GET_WALLET_STATE = (byte) 0x16;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_RESET_PIN = (byte) 0x24;
    private static final byte INS_UNLOCK_PIN = (byte) 0x2C;
    private static boolean HAS_SETUP = false;
    private static OwnerPIN ownerPin;
    private static final byte OWNER_PIN_SIZE = (byte) 6;
    private static final byte OWNER_PIN_TRY_LIMITS = (byte) 5;
    protected static byte[] scratch256;
    protected static DESKey chipKey;
    protected static byte[] masterDerived;

    public BiXinWalletApplet() {
        Crypto.init();
        Bip32Cache.init();
        scratch256 = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        masterDerived = new byte[64];
        chipKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        ownerPin = new OwnerPIN(OWNER_PIN_TRY_LIMITS, OWNER_PIN_SIZE);
        reset();
    }

    private static void reset() {
        Crypto.random.generateData(scratch256, (short) 0, (short) 16);
        chipKey.setKey(scratch256, (short) 0);
        Util.arrayFillNonAtomic(scratch256, (short) 0, (short) 16, (byte) 0x00);
    }

    private static boolean isContactless() {
        return ((APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A);
    }
    private static void storeOnWayPrivate(byte[] buffer, short offset, byte derivationSize, byte i) {
        for (; i < derivationSize; i++) {
            Util.arrayCopyNonAtomic(buffer, (short) (offset + 4 * i), scratch256, Bip32.OFFSET_DERIVATION_INDEX, (short) 4);
            if (!Bip32.derive(buffer)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Bip32Cache.storePrivate(buffer, (byte) (i + 1), scratch256);
        }
    }

    private static void handleGetExtendedPublicKey(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        byte derivationSize = buffer[offset++];
        if (Crypto.ecdh == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte i = findNicePrivate(buffer, derivationSize);
        storeOnWayPrivate(buffer, offset, derivationSize, i);
        Crypto.initTransientPrivate(scratch256, (short) 0);
        Crypto.ecdh.init(Crypto.transientPrivate);
        Crypto.ecdh.generateSecret(Secp256k1.SECP256K1_G, (short) 0, (short) Secp256k1.SECP256K1_G.length, buffer, (short) 1);
        Crypto.compressPublicKey(buffer, (short) 0);
        Util.arrayCopyNonAtomic(scratch256, (short) 32, buffer, (short) 33, (short) 32);
        apdu.setOutgoingAndSend((short) 0, (short) 65);
    }
    private static void handleSetup(APDU apdu) throws ISOException {
        if (HAS_SETUP) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        if (!updatePin(buffer, offset)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        offset += OWNER_PIN_SIZE + 1;
        byte keyLength;
        keyLength = buffer[offset++];
        if (keyLength == 0) {
            keyLength = DEFAULT_SEED_LENGTH;
            Crypto.random.generateData(scratch256, (short) 0, keyLength);
        } else {
            if ((keyLength < 0) || (keyLength > DEFAULT_SEED_LENGTH)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
                Util.arrayCopyNonAtomic(buffer, offset, scratch256, (short) 0, keyLength);
        }
        Bip32.deriveSeed(keyLength);
        Crypto.initCipher(chipKey, true);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short) 0, DEFAULT_SEED_LENGTH, masterDerived, (short) 0);
        HAS_SETUP = true;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
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
                        handleSetup(apdu);
                        break;
                    case INS_GET_WALLET_STATE:
                        handlerGetFirmwareStateInfo(apdu);
                        break;
                    case INS_EXT_GET_EXTENDED_PUBLIC_KEY:
                        handleGetExtendedPublicKey(apdu);
                        break;
                    case INS_VERIFY_PIN:
                        handleVerifyPin(apdu);
                        break;
                    case INS_UNLOCK_PIN:
                        handleUnlockPin(apdu);
                        break;
                    case INS_RESET_PIN:
                        handlerRestPin(apdu);
                        break;
                    case INS_EXPORT_MASTER_DERIVED:
                        checkAccess();
                        handlerExport(apdu);
                        break;
                    case INS_SIGN_HASH:
                        checkAccess();
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

    /***
     * export seed
     * */
    private void handlerExportSeed(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(scratch256, (short) 0, buffer, (short) 0, DEFAULT_SEED_LENGTH);
        apdu.setOutgoingAndSend((short) 0, DEFAULT_SEED_LENGTH);
    }

    /***
     * update pin value
     * */
    private void handlerRestPin(APDU apdu) {
        if (!HAS_SETUP) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        if (buffer[offset++] != OWNER_PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (!ownerPin.check(buffer, offset, OWNER_PIN_SIZE)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        offset += OWNER_PIN_SIZE;
        updatePin(buffer, offset);
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void handleUnlockPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte offset = ISO7816.OFFSET_CDATA;
        if (ownerPin.getTriesRemaining() != 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buffer[offset++] != OWNER_PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        ownerPin.resetAndUnblock();
        try {
            if (!ownerPin.check(buffer, offset, OWNER_PIN_SIZE)) {
                for (;ownerPin.getTriesRemaining() > 0;) {
                    ownerPin.check(buffer, offset, OWNER_PIN_SIZE);
                }
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    private void handlerGetFirmwareStateInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = (HAS_SETUP ? (byte) 1 : (byte) 0);
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }


    private static boolean updatePin(byte[] buffer, short offset) {
        byte ownerPinSize = buffer[offset++];
        if (ownerPinSize != OWNER_PIN_SIZE) {
            return false;
        }
        try {
            ownerPin.update(buffer, offset, OWNER_PIN_SIZE);
            ownerPin.resetAndUnblock();
            buffer[0] = 1;
        } catch (PINException e) {
            buffer[0] = 0;
        }
        return true;
    }

    private static void checkAccess() {
        if (!HAS_SETUP) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (!isContactless() && !ownerPin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private static void handleVerifyPin(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        if (!HAS_SETUP) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short offset = ISO7816.OFFSET_CDATA;
        if (buffer[offset++] != OWNER_PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayFillNonAtomic(scratch256, (short) 0, OWNER_PIN_SIZE, (byte) 0xff);
        Util.arrayCopyNonAtomic(buffer, offset, scratch256, (short) 0, OWNER_PIN_SIZE);
        if (!ownerPin.check(scratch256, (short) 0, OWNER_PIN_SIZE)) {
            byte tryLeft = ownerPin.getTriesRemaining();
            buffer[0] = 0;
            buffer[1] = tryLeft;
            if (tryLeft == 0) {
                //  reset(); todo: add the policy  dealing with  try limit be zero
            }
        } else {
            buffer[0] = 1;
            buffer[1] = 0;
        }
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }

    private void handleSign(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        byte derivationSize = buffer[offset++];
        byte i = findNicePrivate(buffer, derivationSize);
        if (i < derivationSize) {
            storeOnWayPrivate(buffer, offset, derivationSize, i);
        }
        offset += (short) (derivationSize * 4);
        Crypto.signTransientPreComputedHash(scratch256, (short) 0, buffer, offset, buffer, (short) 0);
        short signatureSize = (short) ((short) (buffer[1] & 0x00ff) + 2);
        apdu.setOutgoingAndSend((short) 0, signatureSize);
    }

    private static byte findNicePrivate(byte[] buffer, byte derivationSize) {

        if (derivationSize > MAX_DERIVATION_PATH) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        Crypto.initCipher(chipKey, false);
        Crypto.blobEncryptDecrypt.doFinal(masterDerived, (short) 0, DEFAULT_SEED_LENGTH, scratch256, (short) 0);
        return Bip32Cache.copyPrivateBest(buffer, derivationSize, scratch256);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        new BiXinWalletApplet().register(bArray, (short) (bOffset + 1), bLength);
    }
}
