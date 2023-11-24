from setup import IMDS_PKG
from extract import generateUser
from encrypt import encrypT
from trapdoor import trapdooR
from test import identitySearch , keywordSearch
from decrypt import func
import random
from charm.toolbox.pairinggroup import ZR, G1, G2

# setup
pkg=IMDS_PKG()
params=pkg.generate_params()

# Extract
doctor_id='doctor@gmail.com'
patient_id='patient@gmail.com'
cloud_id="cloudserver@gmail.com"
hospital_id="hospital@gmail.com"
dataConsumer_id="dataconsumer@gmail.com"

skt, qkt = generateUser(params,doctor_id)
ski, qki = generateUser(params,patient_id)
skl, qkl = generateUser(params,cloud_id)
skj, qkj = generateUser(params,hospital_id)
skk, qkk = generateUser(params,dataConsumer_id)


val=random.randint(3,10)
del_i = params['group'].random(G1)
val2=random.randint(1,val)
del_arr=[params['group'].random(G1)]*val
del_arr[val2-1]=del_i

EMR = {
    "name": "User",
    "data": "sensitive medical data health serious disease covid"
}
print(str(EMR))

keywords = ['medical', 'data', 'covid']
n = len(keywords)

print('We are at BCT-IMDS-Encrypt function ')
idi, idt,idk,idl, idj=patient_id,doctor_id,dataConsumer_id,cloud_id,hospital_id
wi,R_t,V_t,C_3,C_id,t_i=encrypT(params,EMR, qki, qkl, skt, ski, qkt, idi, idt, del_i, keywords, idj)
print("C3",C_3)

print('We are at BCT-IMDS-Trapdoor function ')
T_w,T_id,t_i1,w_j,S_ik=trapdooR(params,skk,ski,qki,qkk,idi,idk,del_i,keywords)
# print(T_w,T_id,t_i1,w_j,S_ik)

print('We are at BCT-IMDS-Test  --> BCT-IMDS-Identity Search function ')
del_inew,flag=identitySearch(params,T_id,qki,C_id,del_arr)
if str(del_i)==str(del_inew):
    print("True found")
if flag:
    print('Indentity of patient found!!')

print('We are at BCT-IMDS-Test  --> BCT-IMDS-Keyword Search function ')
S_lk1,Eslk_Rt,Eslk_Vt,Eslk_H1Vl,Eslk_temp=keywordSearch(params,idl,idk,skl,qkl,t_i,t_i1,ski,skk,qkk,C_3,R_t,V_t,w_j,keywords)
# print(S_lk1,Eslk_Rt,Eslk_Vt,Eslk_H1Vl,Eslk_temp)

emr=func(params,S_ik,S_lk1,Eslk_Rt,Eslk_Vt,Eslk_H1Vl,Eslk_temp,ski,R_t,skl)
print(emr)
