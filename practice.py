def make_product(name, price, in_stock):
    product = {}
    product["name"] = name
    product["price"] = price
    product["in_stock"] = in_stock
    product["on_sale"] = price < 20
    return product

s = make_product("Basketball", 5.533,False)
print(s)
print(s["on_sale"])

def label(product):
    if product["on_sale"]:
        return f"{product['name']} - ${product['price']:.2f} (SALE)"
    else:
        return f"{product['name']} - ${product['price']:.2f}"

print(label(s))

def restock(product):
    product["in_stock"] = True
t = make_product("Football",20,False)
restock(s)
print(s["in_stock"])


def productlist(yurr):
    prlist = []
    for name, price, in_stock in yurr:
        prlist.append(make_product(name, price, in_stock))
    return prlist

def cheapest(products):
    for p in products:
        cheapest = p[1]
        if p[1] < cheapest:
            cheapest = [p[1]]
            #print (cheapest)
        return cheapest

yurr =[("Jersey",180,True),("Shorts",50,True),("Joggers",90, True),("Jordans",230, True)]
items = productlist(yurr)
print(cheapest(yurr))
    


