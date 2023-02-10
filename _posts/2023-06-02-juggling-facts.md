---
title: Hack The Box - Juggling Facts
date: 2023-02-06 00:28:00 -500
categories: [ctf,hack the box]
tags: [writeup,walkthrough,php,code review]
---

Today I was feeling inspired and decided to give a try to a HackTheBox challenge. I decided to go for the *Juggling facts* one. This is a Web challenge which was introduced in the *HackTheBoo* beginner competition and thus it has difficult *Very Easy* (I said I was inspired, not that I was going to solve some *Enigma*-level challenge, so calm down).

# Understanding the Website

Apart from taking a look at the instance, we also get the application's source code. I like starting by  taking a look at it and getting an idea of what the website will do before I actually see it. This way I feel like I understand more how it works and I get a first clue on potential vuls or attack vectors. 

The first file I look at is `entrypoint.sh`, since it looks like a good entry point (*badum tss*). I can see there that the application is using a `mysql` DB, which has two relevant columns in its one and only table: `fact` and `fact_type`. We also see all the inserts into the DB, and basically `fact` are html elements, and `fact_type` can be either 'spooky' or 'not_spooky'.  There is also one extra insert, which has the value:

* fact = `HTB{f4k3_fl4g_f0r_t3st1ng}`
* fact_type = `secrets`

So the flag will be in the database, and we will probably need to access it through the `fact_type = secrets`. Let's keep moving. 

Both in `entrypoint.sh` and in `index.php` I can see that there is a user `admin`, with password `M@k3l@R!d3s$`, which works on host `localhost`, so I am not sure if that will work on the real website or only on this test version. 

Looking at `index.php` it looks like we will see three buttons, which will load spooky facts, not_spooky facts or secret facts. 

On `FactModel.php`, the SELECT query to the database takes place. As expected, it searches depending on the `fact_type` column. This method is called `get_facts()`, let's see where this is called (and so, where we will need to access).

`get_facts()` is only called from the `IndexController.php`. Three times: one for each of the `fact_types` there are (*spooky*, *not_spooky* and *secrets*). This is inside a *switch* conditional, in which in which we need that `$jsondata['type'] == 'secrets'`:

```php
switch ($jsondata['type']){
    case 'secrets':
        return $router->jsonify([
            'facts' => $this->facts->get_facts('secrets')
        ]);
    . . .
}
```

Looking at this file and at `index.php`, it seems like `$jsondata` will be some data arriving from a `POST` request. This data will come in a json format, and it needs to carry a `type` element. The only thing is that... oh oh

```php
if ($jsondata['type'] === 'secrets' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1'){
        return $router->jsonify(['message' => 'Currently this type can be only accessed through localhost!']);
}
```

We will not be able to access localhost on the server, so when we try to retrieve the flag, we will always enter this condition. 

Let's start the instance and check if we understood everything correctly until now. We can see the three buttons mentioned before, and when we try to press the *secrets* one, we get the following response (intercepting with burpsuite): 

![burp request](/images/juggling_request.png)

So we understood everything correctly so far. Now, it's time to solve this.

# Type Juggling in PHP

Because of the order of the two checks, it looks like we will never be able to make it to the mysql query (the `get_facts('secrets')` call): 

```php
if ($jsondata['type'] === 'secrets' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1'){
        return $router->jsonify(['message' => 'Currently this type can be only accessed through localhost!']);
}

switch ($jsondata['type']){
    case 'secrets':
        return $router->jsonify(['facts' => $this->facts->get_facts('secrets')]);
    case 'spooky':
        return $router->jsonify(['facts' => $this->facts->get_facts('spooky')]);
    case 'not_spooky':
        return $router->jsonify(['facts' => $this->facts->get_facts('not_spooky')]);  
    default:
        return $router->jsonify(['message' => 'Invalid type!']);
}
```

However, there is a way. In PHP there is this thing called **type juggling**. In this programming language, the type of a variable is decided by the value assigned to it, and not the other way around. That means that when we assign a value of a different type, the variable's type changes too. Type juggling is the way that PHP has to deal with dynamically changing values of a variable. 

Because of this performance, there are two ways of comparing equality between variables in PHP. 
1. `==`  loose comparison : compares two variables after type juggling.
2. `===` or strict comparison : compares two variables AND their types.

[Here](https://www.php.net/manual/en/types.comparisons.php) we can see comparison tables to understand how these operators behave with variables of the same and different types. 

For this challenge, we can take advantage of the fact that the two checks are done with different operators, and so we can actually get different results. We need to accomplish the following:

* Send a request with the json data containing an element `type`
* `$jsondata['type'] === 'secrets' --> FALSE`
* `$jsondata['type'] == 'secrets' --> TRUE` ([here](https://www.php.net/manual/en/control-structures.switch.php) we can see that the `switch` structure performs a loose comparison or `==`).

Looking at the [comparison tables](https://www.php.net/manual/en/types.comparisons.php), we see that:
![comparison table loose](/images/juggling_loose.png)
![comparison table strict](/images/juggling_strict.png)

Which means that if we send the json data with the value `type = true`, that will fail the first check (and avoid the localhost restriction), and since the `secrets` query is the first one, it will match that one, since `true == 'secrets'`, and perform the request. Let's see if it works: 

![flag](/images/juggling_flag.png)

BINGO! And the flag is `HTB{juggl1ng_1s_d4ng3r0u5!!!}`