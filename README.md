# Multi Signature Access Control
Extends OpenZeppelin Access Control to include a basic multi signature modifier and a vote kick function

## Objective
This extension was thought as a mean to better secure key contracts of small groups. Requiring multi signature to perform given actions helps secure the contract funds from an Owner hacked wallet, for example.

## TODO
In the current version the contract provides "Execution Tickets" for admins to execute actions.
The final objective is to also specify the supported action inputs.
