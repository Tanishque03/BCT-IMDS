from AES import AESCipher
from charm.toolbox.pairinggroup import ZR

def identitySearch(params,T_id,qk_i,C_id,del_arr):
    flag=False
    for del_i in del_arr:
        temp_hash=params['H1'](str(params['e'](qk_i,del_i)))
        if C_id==T_id*((temp_hash)**-1):
            
            flag=True
            break
    return del_i,flag

def keywordSearch(params,id_l,id_k,sk_l,qk_l,t_i,t_i1,sk_i,sk_k,qk_k,C_3,R_t,V_t,w_j,keywords):
    # step 1
    flag=False
    for word in keywords:
        temp_21=params['e'](params['H0'](word),sk_i)**(t_i*t_i1)
        temp_12=params['e'](params['H0'](w_j),sk_i)**(t_i*t_i1)
        if str(temp_21*C_3)==str(temp_12*(params['e'](sk_i,R_t))):
            print("Keyword match found")
            flag=True
            break
    if not flag:
        print("Keyword match not found")
        return
    
    # step 2
    f_l=params['group'].random(ZR)
    V_l=f_l*params['P']
    psi_l=params['H1'](str(V_l)+str(params['e'](sk_l,qk_k)))
    # CS_l sent {V_l,psi_l} to DC_k
    
    # step 3
    psi_l1=params['H1'](str(V_l)+str(params['e'](sk_k,qk_l)))
    if psi_l!=psi_l1:
        return
    
    # step 4
    f_k=params['group'].random(ZR)
    V_k=f_k*params['P']
    psi_k=params['H1'](str(V_k)+str(params['e'](sk_k,qk_l)))
    # DC_k sent {V_k,psi_k} to CS_l

    # step 5
    psi_k1=params['H1'](str(V_k)+str(params['e'](sk_l,qk_k)))
    if psi_k!=psi_k1:
        return

    id_l,id_k=str(id_l),str(id_k)
    # step 6
    S_lk1=params['H1'](id_l+id_k+str(V_l)+str(V_k)+str(f_l*V_k))

    S_lk2=params['H1'](id_l+id_k+str(V_l)+str(V_k)+str(f_k*V_l))

    S_lk3=params['H1'](id_l+id_k+str(V_l)+str(V_k)+str(f_l*f_k*params['P']))

    if S_lk1!=S_lk2 or S_lk2!=S_lk3 or S_lk1!=S_lk3:
        print('Formed Session keys did not match ')
        return
    
    cipher = AESCipher(str(S_lk1))
    Eslk_Rt=cipher.encrypt(str(R_t))
    Eslk_Vt=cipher.encrypt(str(V_t))
    Eslk_H1Vl=cipher.encrypt(str(params['H1'](str(V_l))))
    Eslk_temp=cipher.encrypt(str(params['e'](sk_l,R_t)))
    return S_lk1,Eslk_Rt,Eslk_Vt,Eslk_H1Vl,Eslk_temp
