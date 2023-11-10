
def generateUser(params,idu):
    qku = params['H0'](idu)
    sku = params['s'] * qku
    return sku, qku