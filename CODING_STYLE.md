

# CODING STYLE AND GUIDELINES

Smart contracts are contracts. Just as traditional legal contracts are written so parties can read and understand terms before signing, smart contracts must be readable by non-technical users before they interact.

We optimize for code readability.

Avoid unecessary comments. Code should be obvious and self documenting.

Comments should be used only for what can not be easily deduced, inferred or understood by reading the code.

Avoid hardcoded strings and magic numbers, instead use constants with clear naming that make the underlying logic obvious.

Use snake_case for functions and variables - much easier to read than camelCase, specially for long names.

Write with a lawyer mindset - code must be unambiguous and not open to different interpretations.

Strongly favor long and descriptive names for functions and variables vs brevity and acronyms.   Good example:  function claim_slash_for_unproved_vote_counting_challenge( uint proposal_id, uint vote_counting_claim_index, uint challenge_id ) public returns ( uint coins_rewarded )

Internal or private variables and functions should be prefixed with an underscore. Function arguments should not be prefixed with an underscore.

Each instruction should ideally be on a single line. Avoid instructions that span multiple lines unless they make the intent much clearer.

Spacing:
- Use spaces to create semantic groups:  `if(  is_valid  )  process( data );`
- Double spaces in conditionals align with declarations and group multi-checks:  `if(  a > 0  &&  b > 0  )`
- Bad:  `if(amount>0)transfer(amount);`   Good:  `if(  amount > 0  )  transfer( amount );`
- Exception: type casts have no inner spaces:  `address(token)`  `IERC20(msg.sender)`

Separate related instructions with an empty line. Like:

```solidity
    uint some_var  =  get_something( );
    if(  some_var == 1  )  call_external( );

    uint another_var  =  get_something_else( );
    if(  another_var > 0  )  another_call( );

    if(  some_var == another_var  )  do_this( );
```

Never do complex comparison.   This is bad:  if( now > snapshot + delay )   This is good:  if( now > eligible_time )

Wherever there is a point in code that could be susceptible to a security concern, like a place where security is critical and non-obvious, we must have a warning in the form of, for example:  // *SECURITY*  -  The ids generated here might be predicted therefore caution is advised.

Code must be indented perfectly. Opening braces follow this convention:
- `contract`/`library`/`interface`: opening brace on same line
- `function`/`if`/`while`/`for`/`else`: opening brace on new line

```solidity
contract Some {
}

library SomeLib {
}

function some( )
{
}

if(  x == y  )
{
}
```

Function signatures:
- `external`/`public`: visibility on new line (attack surface stands out)
- `internal`/`private`: visibility on same line (≤160 chars)
- Modifiers separated by double spaces for security visibility: `external  payable  nonReentrant( LOCK )`

```solidity
function _smart_exit( bytes20 key ) private

function create_bond( bytes32 commitment_hash, TokenAmount memory stake )
external  payable  nonReentrant( LOCK_BONDS )
```

End comments with a dot.

Avoid the negate operator (!) in boolean comparisons. Make explicit comparisons to false. Like:  if(  is_something == false  )

Avoid the post-increment or pre-increment operator bc non-tech users may not clearly understand that.  Bad:  somevar++   Bad:  ++somevar   Good:  somevar  =  somevar + 1;
You may use the += or -= or any of those operators if the line would get too long otherwise.

if possible and the line doesnt get too long in contrast with the others keep a singular intent expression in one line like this: if(  stored_token_amount < amount  ) revert Error( "message" );

You are free to extend the line length up to 160 chars - each line is supposed to contain a full cohesive semantic instruction.

When importing from other files, use clean remapping aliases as specified in foundry.toml. For Definitions.sol just use:  import "@BondRoute/Definitions.sol"

Test files must also be self documenting, easy to follow, and make themselves evident thru assert messages.

All the specified rules in this document are general principle guidelines and may have their own justified exceptions.
