from AES import AESCipher
import random
from charm.toolbox.pairinggroup import ZR

# Encrypt the data
def encrypT(params,EMR, qki, qkl, skt, ski, qkt, idi, idt,del_i, keywords, idj):

    EMR = int(params['H1'](str(EMR)))
    print(f'EMR : {EMR}')

    # step 1
    r_t = params['group'].random(ZR)
    R_t = r_t * params['P']
    tmp_pair = str(params['e'](qki+qkl, r_t * params['P0']))
    tmp_hash = int(params['H1'](tmp_pair))
    # print(f'STR : {str(tmp_pair)}')
    print(f'TMP_HASH : {tmp_hash}, type: {type(tmp_hash)}')
    # print(type(EMR))
    V_t = EMR ^ tmp_hash
    # print(f'VTA : {Vt}')
    a_t = params['group'].random(ZR)
    T_t = a_t * params['P']
    tmp_pair2 = str(params['e'](skt, qki))
    sigma_t = params['H1'](str(T_t) + tmp_pair2)
    print(f'Sigma T : {sigma_t}')
    # It will send T_t and sigma_t to DOi
    # return {T_t, sigma_t}

    # step 2
    # Now the DOPi works on this data
    tmp_pair3 = str(params['e'](ski, qkt))
    sigmat1 = params['H1'](str(T_t) + tmp_pair3)
    if sigma_t != sigmat1:
        print(f'Invalid request. Terminating Session...')
        return
    print(f'Successful match. Assuming legit request')

    # step 3
    a_i = params['group'].random(ZR)
    T_i = a_i * params['P']
    sigma_i = params['H1'](str(T_i) + tmp_pair3)
        
    # DOi sends this data to Dt
    # return {T_i, sigma_i}

    # step 4
    # Now Dt will work on the data
    prod1 = str(a_i * T_t)
    prod2 = str(a_t * T_i)
    prod3 = str(a_i * a_t * params['P'])

    # Key with DOi
    Sit1 = params['H1'](idi + idt + str(T_i) + str(T_t) + prod1)

    # Key with Dt
    Sit2 = params['H1'](idi + idt + str(T_i) + str(T_t) + prod2)

    # Both keys are quivalent to this
    Sit3 = params['H1'](idi + idt + str(T_i) + str(T_t) + prod3)

    print(f'Sit1 : {Sit1}')
    print(f'Sit2 : {Sit2}')
    print(f'Sit3 : {Sit3}')

    # Now this data is encrypted my the Sit and sent to the DOi
    cipher = AESCipher(str(Sit1))
    # Choose a random keyword
    wi = random.choice(keywords)
    Esit = cipher.encrypt(wi)
    print(f'Keyword : {wi}\nEncrypted keyword : {Esit}')

    # step 5
    # Now the DOi will decrypt the message with the common session key
    cipher2 = AESCipher(str(Sit2))
    decrypt_keyword = cipher2.decrypt(Esit)
    print(f'Decrypted keyword : {decrypt_keyword}')

    # step 6
    t_i = params['group'].random(ZR)
    C_1 = t_i * ski
    C_2 = t_i * params['H0'](decrypt_keyword)
    ti_inv = t_i ** -1
    print(f'ti : {t_i}')
    print(f'C1 : {C_1}')
    print(f'C2 : {C_2}')
    print(f'ti_inverse: {ti_inv}')
    
    prod4 = ti_inv * params['H0'](del_i)
    C_id = params['e'](C_1, prod4)
    C_i = (C_1, C_2)
    
    print(f'Cid : {C_id}\n')

    # Now DOi sends Esit(Ci) and Esit(Cid)
    Esit_ci = cipher2.encrypt(str(C_i))
    Esit_cid = cipher2.encrypt(str(C_id))

    print(f'Esit(ci) : {Esit_ci}\n')
    print(f'Esit(cid) : {Esit_cid}\n')

    # step 7
    # Now Dt will decrypt the data
    decrypt_ci = cipher.decrypt(Esit_ci)
    
    print(f'Ci : {C_i}\n')
    print(f'Decrypt Ci : {decrypt_ci}\n')
    if str(C_i)==str(decrypt_ci):
        print("decrypted_ci and C_i matched")

    C_3 = params['e'](qkl, r_t*params['P0'])
    A_i = (r_t * (skt + params['H0'](wi)) * params['P1']) + (r_t * params['H0'](wi) * params['P'])
    exp = params['H1'](str(r_t * (skt + params['H0'](wi))))
    J_i = params['e'](params['P'], params['P1']) ** exp
    X_bar = []
    for i in range(1, len(keywords)+1):
        temp = r_t * (params['H0'](wi) ** i) * params['P']
        X_bar.append(temp)

    print(f'C3 : {C_3}\n')
    print(f'Ai : {A_i}\n')
    print(f'exp : {exp}\n')
    print(f'X_bar : {X_bar}\n')
    print(f'Ji : {J_i}\n')

    # Consensus protocol for private blockchain
    # Dt selects rt_bar
    rt_bar = params['group'].random(ZR)
    T_del_i = (rt_bar ** -1) * del_i
    sigma_del_i = params['e'](rt_bar * qki, T_del_i)
    pid_i = (T_del_i, sigma_del_i, idj)

    # Dt also computes
    alpha_t = rt_bar * params['H1'](str(skt))
    gamma_t = (rt_bar ** -1) * params['H1'](str(skt * del_i))

    print(f'alpha_t : {alpha_t}\n')
    print(f'gamma_t : {gamma_t}\n')
    
    C_wi=(C_i,C_3)
    return wi,R_t,V_t,C_3,C_id,t_i
