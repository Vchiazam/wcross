from flask import jsonify
class Product:
    def __init__(self, price):
        self.create(price)
    def get(self):
        return self.__price
    def create(self, value):
        if value < 0:
            print("no")
        self.__price = value
    def __str__(self):
        return f"{self.__price}"
    price = property(get, create)
    
product = Product(4)
print(product)

oo = '["tee", "cent", "ten", "tern", "teen", "rent" ]'
#po = [use]
#po.append(1)
nn = 10
#use = sum(po , nn)
#print(use)
name = "tee ten tern teen rent"
kl = name.split(" ")
print(kl)
kl.append("when")
print(kl)
till = ["tee", "cent", "ten", "tern", "teen", "rent" ]
til = ''
print(type(til))
print(list(til))
ken = list(til)
ken.append("then")
print(ken)
for x in till:
    til += ' ' + x
print(til)


print("______________________")
#x = 'center enter tree recent net'
x = 'center then'
if x == None:
    x = []
else:
    x = x.split(" ")
    x = list(x)
print(x)
print("_______________________")
x.append('now')
print(x)
ab = ''
for a in x:
    ab += ' ' + a

print(ab)
qa = " vvv"
print(qa)
qa = qa.strip()
qa = qa.split(" ")
print(type(qa))

print("_________")
tt = ["tee", "cent", "ten", "tern", "teen", "rent" ]
tb = ' '.join(tt)
print(tb)
data = [(3, "Dranca", 123456), (4, "franca", 123456), (2, "Faniel", 123456), (5, "franca", 123456), (1, "Daniel", 123456), (6, "franca", 123456), (7, "victor", 123456), (8, "esther", 123456), (9, "amarachi", 123456)]
print(type(data))
name = [x[1] for x in data]
id = [x[0] for x in data]
password = [x[2] for x in data]
#ps = {x[1] for x in data: x2 for x in data}
input = 'franca'
pinput = 123456
tup = tuple(data)
#dct = dict((y, x) for x, y, in tup)
#print(dct)
print(tup)
print('__________________')
print(name)
print(id)
print(password)
print('________________')
#print(ps)
#print(tup)
first = {name[i]: id[i] for i in range(len(name))}
second = {id[i]: password[i] for i in range(len(name))}
print(first)
print(second)
print('________________________')
exist = name.count(input)
def login():
    data = [(3, "Dranca", 123456), (4, "franca", 123456), (2, "Faniel", 123456), (5, "franca", 123456), (1, "Daniel", 123456), (6, "franca", 123456), (7, "victor", 123456), (8, "esther", 123456), (9, "amarachi", 123456)]
    name = [x[1] for x in data]
    id = [x[0] for x in data]
    password = [x[2] for x in data]
    first = {name[i]: id[i] for i in range(len(name))}
    second = {id[i]: password[i] for i in range(len(name))}
    input = 'franca'
    pinput = 123456
    exist = name.count(input)
    if exist > 0:
        print("user found")
        me = first[input]
        mme = second[me]
        if mme == pinput:
            print(me, input)
            return jsonify(
                {
                    "id": me,
                    "name": input,
                    "success": True
                }
            )
        else:
            print("wrong password")
    else:
        print("user doesn't exist")
login()