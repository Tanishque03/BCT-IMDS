from AES import AESCipher

def func(params,S_ik,S_lk,Eslk_Rt,Eslk_Vt,Eslk_H1Vl,Eslk_temp,sk_i,R_t,sk_l):
    cipher = AESCipher(str(S_lk))
    decrypt_keyword = cipher.decrypt(Eslk_Rt)
    print(f'Decrypted keyword : {decrypt_keyword}')

    cipher2 = AESCipher(str(S_ik))
    Esik_Rt=cipher2.encrypt(decrypt_keyword)

    R_t_decrypted=cipher2.decrypt(Esik_Rt)
    print(f'Decrypted keyword R_t from DC_k is equal to R_t sent by CS_l ??: {type(decrypt_keyword)==type(R_t_decrypted)}')
    encrypted=cipher2.encrypt(str(params['e'](sk_i,R_t)))

    decrypted=cipher2.decrypt(encrypted)
    tempmap=cipher.decrypt(Eslk_temp)
    map_SKI_RT=params['e'](sk_i,R_t)
    map_SKL_RT=params['e'](sk_l,R_t)
    V_t=cipher.decrypt(Eslk_Vt)
    V_t=int(params['H1'](str(V_t)))
    EMR=V_t^(int(params['H1'](str(map_SKL_RT*map_SKI_RT))))
    return EMR