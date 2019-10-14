#### HandleSetup
- Description

  init PIN and Seed

- Command

| CLA  | INS  |  P1  |  P2  |  LC  |  LE  |
| :--: | :--: | :--: | :--: | :--: | :--: |
|  00  |  08  |  00  |  00  |  varible  |  00  |

- *Input data*

|            **Description**             | **Length** |
| :------------------------------------: | :--------: |
|                PINSize                 |     1      |
|                PINValue                |     6      |
| KeyLength(may set 0, used the default) |     1      |
|                KeyValue                |  variable  |

- *Output data*

|    **Description**    | **Length** |
| :-------------------: | :--------: |
| 1(success) or 0(fail) |     1      |


```

 Eg :  >> 00 20 00 00 07 06 11 22 33 44 55 66 

		<< 01 90 00  
		// 01 indicates success

```

#### HandleGetExtendedPublicKey

- Description

  This command returns the X component of a public key and a signature to recover the Y component

  **Note** : **only used  when hard driven (the index more than 0x80000000)**

- Command

| CLA  | INS  |  P1  |  P2  |    LC    |  LE  |
| :--: | :--: | :--: | :--: | :------: | :--: |
|  00  |  10  |  00  |  00  | variable |  0   |

- *Input data*

|                 **Description**                  | **Length** |
| :----------------------------------------------: | :--------: |
|                                                  |            |
|                                                  |            |
| Number of BIP 32 derivations to perform (max 10) |     1      |
|       First derivation index (big endian)        |     4      |
|        Next derivation index (big endian)        |     4      |

- *Output data*

|    **Description**    | **Length** |
| :-------------------: | :--------: |
| Compressed  publicKey |     33     |
|       Chaincode       |     32     |

#### HandleSign
- Description

  Sign  PreComputedHash

- Command

| CLA  | INS  |  P1  |  P2  |    LC    |  LE  |
| :--: | :--: | :--: | :--: | :------: | :--: |
|  00  |  12  |  00  |  00  | variable |  00  |

- *Input data*

|        **Description**        | **Length** |
| :---------------------------: | :--------: |
|             Depth             |     1      |
| Derivation index (big endian) |  4/depth   |
|       Hash to be signed       |     32     |

- *Output data*

| **Description** | **Length** |
| :-------------: | :--------: |
|    Signature    |  variable  |

#### HandleExport
- Description

  Export  masterChainCode and master PrivateKey

- Command

| CLA  | INS  |  P1  |  P2  |  LC  |  LE  |
| :--: | :--: | :--: | :--: | :--: | :--: |
|  00  |  14  |  00  |  00  |  00  |  00  |

- *Input data*

- *Output data*

|            **Description**            | **Length** |
| :-----------------------------------: | :--------: |
| master PrivateKey and masterChainCode |     64     |

#### HandleVerifyPIN
- Description

  Verify PIN first

- Command

| CLA  | INS  |  P1  |  P2  |         LC          |  LE  |
| :--: | :--: | :--: | :--: | :-----------------: | :--: |
|  00  |  20  |  00  |  00  | variable(may be 07) |  00  |

- *Input data*

| **Description** | **Length** |
| :-------------: | :--------: |
|     PINSize     |     1      |
|    PINValue     |     6      |
|                 |            |

- *Output data*

|                       **Description**                        | **Length** |
| :----------------------------------------------------------: | :--------: |
| 0 \|\| the try limit left when failed ,  10  always indicates success |     1      |

```js
eg:
>> 00 08 01 00 00 (APDU CASE2)
<< 00 05 90 00

eg: verify pin
>> 00 08 00 00 07 06 11 22 33 44 55 66 00 (APDU CASE4)
<< 01 90 00
```
#### HandleGetFirmwareStateInfo
- Description

    get the card state info

- Command

| CLA  | INS  |  P1  |  P2  |  LC  |  LE  |
| :--: | :--: | :--: | :--: | :--: | :--: |
|  00  |  16  |  00  |  00  |  00  |  00  |

- *Input data*

- *Output data*

|        **Description**         | **Length** |
| :----------------------------: | :--------: |
| 1(has inited ) or 0(need init) |     1      |


#### HandleRestPIN
- Description

  reset the pin code

- Command

| CLA  | INS  |  P1  |  P2  |         LC          |  LE  |
| :--: | :--: | :--: | :--: | :-----------------: | :--: |
|  00  |  24  |  00  |  00  | variable(may be 07) |  00  |

- *Input data*
| **Description** | **Length** |
| :-------------: | :--------: |
|   oldPINSize    |     1      |
|   oldPINValue   |     6      |
|   newPINSize    |     1      |
|   newPINValue   |     6      |

- *Output data*

```js
eg:
>> 00 16 00 00 0E 06 11 22 33 44 55 66 06 11 11 11 11 11 11 (APDU CASE3)
<< 01 90 00

>> 00 16 00 00 0E 06 11 22 33 44 55 67 06 11 11 11 11 11 11 (APDU CASE3)
<< 6A 80

```
#### HandleUnlockPIN
- Description

   **NOTE**: only be used  when pin has no try limits left 

- Command

| CLA  | INS  |  P1  |  P2  |    LC    |  LE  |
| :--: | :--: | :--: | :--: | :------: | :--: |
|  00  |  2C  |  00  |  00  | variable |  00  |

- *Input data*


| **Description** | **Length** |
| :-------------: | :--------: |
|     PINSize     |     1      |
|    PINValue     |     6      |

- *Output data*

```js
eg:
>> 00 18 00 00 07 06 11 22 33 44 55 67 (APDU CASE3)
<< 90 00
```