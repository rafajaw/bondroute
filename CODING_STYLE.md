

# CODING STYLE AND GUIDELINES

We optimize for code readability.

Avoid unecessary comments. Code should be obvious and self documenting.

Comments should be used only for what can not be easily deduced, inferred or understood by reading the code.

Avoid magic numbers, instead use constants with clear naming that make the underlying logic obvious.

Code should be able to be read by even a non programmer. Use snake case for functions and variables as they make it much easier to read.

Each instruction should ideally be on a single line. Avoid instructions that span multiple lines unless they make the intent much clearer.

Make lots of usage of spaces. Use spacings to create semantic groups between subinstructions. Like:  if(  is_true( some_val )  )   do_something( );

Use spacings around vars to make them extra readable.   This is bad:  if(now)call(somevar);   This is good:  if( now )  call( somevar );

Separate related instructions with an empty line. Like:

```
    const some_var  =  get_something( );
    if( some_var == 1 )  call_external( );

    const another_thing  =  get_something_else( );
    if( another_thing == 2 )  another_call( );

    if( some_var == another_thing )  do_this( );
```

Never do complex comparison.   This is bad:  if( now > snapshot + delay )   This is good:  if( now > eligible_time )

Specially for smart contracts, we want the contracts to be read by a non technical person! Smart contracts should be written with a lawyer mindset, avoiding any possible dubious interpretation. Code should maximize for clarity. There must be an extra effort to make sure that the code can't be interpreted differently than what it is supposed to be interpreted like.

Wherever there is a point in code that could be susceptible to a security concern, like a place where security is critical and non-obvious, we must have a warning in the form of, for example:  // *SECURITY*  -  The ids generated here might be predicted therefore caution is advised.

Code must be indented perfectly, the braces follow the following convention (inside code omitted):
```
contract Some {
}

function some( )
{
}

const some  =  async ( ) => {
}

while( some )
{
}
```

Internal or private variables and functions should be prefixed with an underscore. Function arguments should not be prefixed with an underscore.

Strongly favor long and descriptive names for functions and variables vs brevity and acronyms.   Good example:  function claim_slash_for_unproved_vote_counting_challenge( uint proposal_id, uint vote_counting_claim_index, uint challenge_id ) public returns ( uint coins_rewarded )

End comments with a dot.

Avoid the negate operator (!) in boolean comparisons. Make explicit comparisons to false. Like:  if( is_something == false )

Avoid the post-increment or pre-increment operator bc non-tech users may not clearly understand that.  Bad:  somevar++   Bad:  ++somevar   Good:  somevar  =  somevar + 1;
You may use the += or -= or any of those operators if the line would get too long otherwise.

if possible and the line doesnt get too long in contrast with the others keep a singular intent expression in one line like this: if(  stored_token_amount < amount  ) revert Error( "message" );

We are not addressing only to devs, we are also addressing to consumers reading a contract.

You are free to extend the line length up to 180 chars - each line is supposed to contain a full cohesive semantic instruction.

All the specified rules in this document are general principle guidelines and may have their own justified exceptions.

