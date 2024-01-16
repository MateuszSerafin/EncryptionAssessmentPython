# EncryptionAssessmentPython

## What is it?
It's my over engineered assessment project from python. We were supposed to create project such as sftp server using python sockets. 

So here is my implementation of secure upload and download. 


## Overview

1. Client generates session keys
2. Client connects to server using session key but authenticates using saved key pair.
3. If server recognizes key performs challenge. After successfully challenge verifies signature and then sends symmetric key. 
 else if server admin allowed for client to register it can provide register code and after confirmation client is "registered"
 else drop connection

4. I don't know really basic file upload/download. Although server makes sure that no one is downloading file while being removed and also some benchmark tools.

## Future Improvements
This was first time i wrote socket application. There were weird issues so i switched slightly how i handle packets and i didn't like it. 

At beginning I used a queue to store packets and handle everything asynchronously but then weird issues started. So i reverted to do it in more sync way.

Overall I am happy how Assessment went I also like this program but handling packets is not clean i would rewrite it if it wouldn't be like 3rd time i was changing it. 
