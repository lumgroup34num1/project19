import hashlib,math,config
from random import randint
from SM2_ECG import *
from Prepare import *


def forge_Satoshi_sig(e,r,s,n,G,P):
    u_=randint(1,n-1)                                               #随机生成u、v
    v_=randint(1,n-1)
    R= ECG_ele_add(ECG_k_point(u_,G),ECG_k_point(v_,P))             #计算伪造签名R'值
    r_=R.x                                                          #r'=R'.x
    s_=(r_*config.inverse(v_, n))%n                                 #s'=r'/v
    e_=(u_*s_)%n                                                    #e'=u'*s'
    return (e_,r_,s_)

def ECDSA_verify(e,r,s,G,P):                                        #对伪造签名验签
    w = config.inverse(s, n)
    R=ECG_ele_add(ECG_k_point((e*w)%n,G),ECG_k_point((r*w)%n,P))
    if(R.x==r):
        return True
    return False

if __name__=='__main__':

    config.set_default_config()                                                                     #设置椭圆曲线参数
    parameters = config.get_parameters()
    point_G = Point(config.get_Gx(), config.get_Gy())
    n = config.get_n()

    P=ECG_k_point(1,point_G)                                                                        #假设中本聪的私钥为1，公钥则为1*G

    real_digest=0x5977d32090f4143bf5365818ea486e26ea53f68e7baf49c3e065a7117c9d4a8                   #中本聪签名的假设摘要值
    realsig_r=61518691557461623794232686914770715342344584505217074682876722883231084339701         #中本聪签名的假设r，s值
    realsig_s=54273397679854571629338298093917192510492979773857829699728440258287077154636
    print(f"已有签名为:\nH(m):{real_digest}\nr:{realsig_r}\ns:{realsig_s}")
    
    e,r,s=forge_Satoshi_sig(real_digest,realsig_r,realsig_s,n,point_G,P)                            #仅使用已有签名伪造新签名

    if(ECDSA_verify(e,r,s,point_G,P)):                                                              #对伪造签名值进行验签
        print(f"伪造成功，伪造签名为\nH(m'):{e}\nr':{r}\ns':{s}")
