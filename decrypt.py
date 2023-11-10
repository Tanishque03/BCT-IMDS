from AES import AESCipher

def func(params,S_ik,S_lk,Eslk_Rt,Eslk_Vt,Eslk_H1Vl,Eslk_temp,sk_i):
    cipher = AESCipher(str(S_lk))
    decrypt_keyword = cipher.decrypt(Eslk_Rt)
    print(f'Decrypted keyword : {decrypt_keyword}')

    cipher2 = AESCipher(str(S_ik))
    Esik_Rt=cipher2.encrypt(decrypt_keyword)

    R_t=cipher2.decrypt(Esik_Rt)
    encrypted=cipher2.encrypt(str(params['e'](sk_i,R_t)))

    decrypted=cipher2.decrypt(encrypted)
    V_t=cipher.decrypt(Eslk_Vt)
    tempmap=cipher.decrypt(Eslk_temp)
    EMR=V_t^(params['H1'](decrypted*tempmap))
    print(EMR)
    return EMR