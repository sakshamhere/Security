https://www.youtube.com/watch?v=ui4l0lBBSlw

# Base score metrics

* Exploitblity Metrics  

These are the conditions before the attack o ccours

> Attack Vector (AV)* 

- N Network  - If the attack comes from the Internet

- A Adjacent Network - If Attack must come from a LAN

- L Local - If the attack can occour only if attacker is loggen in locally to vulnerable machine

- P Physical - If the attacker must have their hands on the vulnerable machine

> Attack Complexity (AC)*

- Low - if it is easy to attack

- High - if it is dufficult to attack

> Privileges Required (PR)*

- N None - If there are no credentials required to perform this attack

- L Low  - If attacker needs to be logged in with a User level account

- H High - If attacker needs to be loggen in with an Admin level account

> User Interaction (UI)*

- N None - If the victim intercation is not required

- R Required - If the victim intercation is not required

> Scope (S)*

- U Unchanged - If attack does not chage/elevates privilages of attacker

- C Changed - If the attack itself changes/elevates the privilages of attacker 

Impact Metrics

(the impact depends on Scope as if S:C then consider impact to a larger scope using C I A)

> Confidentiality (C)*

- N None - If the attacker has not breached of vulnerable component

- L Low - If the attacker has breached some data of vulnerable component

- H High - If the attacker has breached full data of vulnerable component

> Integrity (I)*

- N None - If the attacker has not changed how vulnerable compoenet reponse and so data provide by component is reliable

- L Low - If the attacker has changed partially how vulnerable compoenet reponse and so some data provided by vulnerable compoenent is reliable

- H High - If the attacker has changed completely how vulnerable compoenet reponse and so data provided by component is completely unreliable

> Accessiblity (A)*

- N None - If attack has not caused any Denial of Service (DOS)

- L Low - If attack has caused any Denial of Service (DOS) intermidiatary

- H High - If attack has caused Full Denial of Service (DOS)


* - All base metrics are required to generate a base score. 


# Temporal Metrics 

# Enviornmental Metrics










