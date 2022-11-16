## The JUGGLER (Misc)
```
<?php
include 'secret.php';
$username='Administrator';
$obj=json_decode(file_get_contents('php://input'), true);

if (!empty($obj['username']) && !empty($obj['password'])){
if ($obj['username'] == $username && $obj['password'] = $password){
    echo "Access Granted!";
}
else {
    echo "Wrong password";
}
} else {echo "Empty Params";}
?>

```

This challenge requires us to review the given php code as it contains bugs, there are 5 test cases which it needs to pass before it could give us our flag.
 
 Analyzing the code we could see that  challenge is trying to check the contestant understanding of the commonly found vulnerabilities in php known as **PHP type Juggling** and how they could lead to authentication bypass vulnerability. you could read more of php type juggling [here](https://medium.com/swlh/php-type-juggling-vulnerabilities-3e28c4ed5c09)
  
 Now back to the challenge, for a user to be granted access the user must pass the verification with correct login credentials, the bug in this code is firstly a deserialization flaw, the user input is not correctly filtered, the second bug is the second block of if statment we could clearly see that the comparison operator is using only double equal sign **"=="** if a user simply submit an integer input of 0 would successfully log in as admin, since this will evaluate to True, this is because the secret password would be converted to integer and evaluate to true.

Changing the comparison opeartor from **"=="** to **"==="** correctly passes the check cases and throws our flag.

![image](_images/oie_C7BerbRBduib.png)


## Nimbus prime (OSINT)



An image was given, the challenge was to find the location -the latitude and longitude of the place -

![Phote](_images/chall.jpg)

my first attempt was using [tinyeye](tinyeye.com) to do reverse image search, but nothing came up.
Taking a close look at the pic we could see that it's like a airport or rail way station cause of the people in the pic with luggages,
another thing to observe was the nimbus monument (all harry potter fans should know this :grinning: )).

i went on to google map to search for the nimbus monument, one that is specifically around a station of some sort

 ![staion](_images/oie_SOKYbPKgzbzo.png)

Well the results wasn't that appealing to what i was looking for

my last attempt was using google lens, it brought up a result instantly
![google_lens](_images/google_lens.png)

going to google maps and doing more search on the area i got the exact location

![result](_images/Screenshot_2022-11-04_11_07_20.png)

atlass my intution was correct it was an airport station called "Humberto Delgado Airport" !!!
getting the latt and long and sumbiting it
gave us our flag.....Nice OSINT challenge i really enjoyed it. :laughing: