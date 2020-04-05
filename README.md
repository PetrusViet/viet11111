## I.	AUCTF-2020
## 1.	Extraordinary

On their way back from the market, Alice and Bob noticed a little device on the ground. Next to it was a piece of paper with what looked like a bunch of scrambled numbers on it. It looked completely random. They took it to the lost and found, but on their way they played with it a little bit (don't tell anyone!). The device was never picked up, so we get to play with it a little bit, too. Can you figure out how the device works?

b'6\x1d\x0cT*\x12\x18V\x05\x13c1R\x07u#\x021Jq\x05\x02n\x03t%1\\x04@V7P\\x17aN'

nc challenges.auctf.com 30030


----------------------------------------------------
Đề bài cho chúng ta 1 Bytes Array, có thể đây là kiểu mã hoá xor, thử xor với format của đề xem nào :
```python
	k = 'auctf{'
        c = b'6\x1d\x0cT*\x12\x18V\x05\x13c1R\x07u#\x021Jq\x05\x02n\x03t%1\\x04@V7P\\x17aN'
        t = ''
        j = 0
        for i in c:
                t += chr(int(i)^ord(k[j%len(k)]))
                j += 1
         print(t)
```
và kết quả:
```python
        "Who Liy#fg\x05J3r\x16WdJ+\x04fv\x08x\x15PR(\x1eKU55C6'\x19DT\x15("
```
Như vậy đúng là nó mã hoá xor, nhưng với key dài hơn format flag =)))))))

tiếp tục xem ta có gì:
```python
        nc challenges.auctf.com 30030
```
thử nhập đoạn key 'Who Li' mà chúng ta tìm được vừa nãy xem sao thì kết quả trả về:
```python
        b'6\x1d\x0cT*\x12'
```
nó có vẻ giống với c, điều đó có nghĩa là server sẽ trả về kết quả là text ^ flag.  yebb, nếu như vậy thì ta chỉ cần nhập
một đoạn text bất kỳ, lấy giá trị trả về từ server rồi xor ngược lại với text là ra flag.
làm thôi:
```bash
        $  nc challenges.auctf.com 30030
        > bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        b'\x03\x17\x01\x16\x04\x19\x0cQ\x14Q0=\x10Q7\x11Q=\x1bR\x170=R6\x12=ZUP\x14\x01Z[UP\x1f\x03\x17\x01\x16\x04\x19\x0cQ\
        x14Q0=\x10Q7\x11'
```
and:
```python
        c = b'\x03\x17\x01\x16\x04\x19\x0cQ\x14Q0=\x10Q7\x11Q=\x1bR\x170=R6\x12=ZUP\x14\x01Z[UP\x1f\x03\x17\
        x01\x16\x04\x19\x0cQ\x14Q0=\x10Q7\x11'
        p = ''
        for i in c:
                p += chr(int(i)^ord('b'))
        print(p)
```
ta có kết quả:
```pythone
        'auctf{n3v3R_r3Us3_y0uR_0Tp_872vc8972}auctf{n3v3R_r3Us'
 ```
 
 ### flag: auctf{n3v3R_r3Us3_y0uR_0Tp_872vc8972}
 
 ## 2.Pretty Ridiculous
 
 Eve discovered that a piece of paper had been shoved into her pocket.. what could it be? The message she found can be downloaded at the following link:

(n,e) = (627585038806247, 65537)

https://drive.google.com/file/d/17z7C5i_TOx_838QNPbZvNCKW4DcPCaEF/view?usp=sharing

----------------------------------------------------
đây là 1 bài RSA đơn giản, tìm hiểu về [RSA](https://vi.wikipedia.org/wiki/RSA_(m%C3%A3_h%C3%B3a))

mình sử dụng [factordb](http://factordb.com/) để tách n thành 2 số nguyên tố p, q
giải thôi:
```python
import math

def getModInverse(a, m):
    if math.gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (
            u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m
    
    
    
p = 13458281
q = 46631887
n = 627585038806247
e = 65537
ct = [145213650433152, 4562349440334, 24272724667960, 598242834066721, 89584939111364, 426756492371444, 511701778613016, 551732685650248, 296367799892003, 63113462897284, 198510931603899, 321201931522255, 401044612595398, 542697603423052, 213898535689643, 275839755798105, 185841409622217, 551732685650248, 121188708737752, 401044612595398, 512808963720303, 275839755798105, 198510931603899, 275839755798105, 401044612595398, 174484844253615, 551732685650248, 174486913717420, 575163265381617, 213898535689643, 401044612595398, 49103824223436, 551732685650248, 401044612595398, 598242834066721, 202722428784490, 306606077829794, 53801100921263, 401044612595398, 184805755675232, 405971446461049, 296367799892003, 275839755798105, 275839755798105, 401044612595398, 358054299396778, 4562349440334, 320837325468842, 401044612595398, 202722428784490, 551732685650248, 321201931522255, 228350651363859]

# Compute phi(n)
phi = (p - 1) * (q - 1)

# Compute modular inverse of e
d = getModInverse(e, phi)    
      
# Decrypt ciphertext
pt = ''
for i in ct:
        pt += bytearray.fromhex(str(hex(pow(i, d, n)))[2:]).decode()
        
print("text: ", pt)
```

```python
text:  auctf{R34lLy_Pr1M3s_w1L1_n3vEr_b3_thI5_Sm411_BuT_h3y}
```
### Flag: auctf{R34lLy_Pr1M3s_w1L1_n3vEr_b3_thI5_Sm411_BuT_h3y}

## II. VirSecCon CTF 2020

## 1. Hot Dog

n = 609983533322177402468580314139090006939877955334245068261469677806169434040069069770928535701086364941983428090933795745853896746458472620457491993499511798536747668197186857850887990812746855062415626715645223089415186093589721763366994454776521466115355580659841153428179997121984448771910872629371808169183

e = 387825392787200906676631198961098070912332865442137539919413714790310139653713077586557654409565459752133439009280843965856789151962860193830258244424149230046832475959852771134503754778007132465468717789936602755336332984790622132641288576440161244396963980583318569320681953570111708877198371377792396775817

c = 387550614803874258991642724003284418859467464692188062983793173435868573346772557240137839436544557982321847802344313679589173157662615464542092163712541321351682014606383820947825480748404154232812314611063946877021201178164920650694457922409859337200682155636299936841054496931525597635432090165889554207685

----------------------------------------------------

Ta thấy đây là 1 bài RSA với số e lớn, do 'ed ≡ 1 mod phi' nên khi e lớn thì d sẽ nhỏ.
Chúng ta có 1 phương pháp để tìm d (với d không quá lớn) gọi là [wiener's attack](https://en.wikipedia.org/wiki/Wiener%27s_attack)
loanh qoanh 1 lúc mình tìm được 1 cái [tool](https://github.com/pablocelayes/rsa-wiener-attack)

và đây là kết quả:
```python
d:  40127490441880177477224469176371044914847896019034308382923938039797354608313
flag:  LLS{looks_like_weiners_on_the_barbecue}
```
### flag:  LLS{looks_like_weiners_on_the_barbecue}
