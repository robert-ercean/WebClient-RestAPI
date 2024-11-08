# Cookies


### *Cookies structure*


- Wasn't sure about how cookies may be structured so I chose a double string array `(char **)`
in case the `server` returns multiple session cookies instances.
- `Cookies backlog max` represents the maximum amount of session cookie instances the program
can hold at one time (dynamically allocated)
- After using the provided checker I noticed that every cookie instance is just `one` long
string but I didn't modify my implementation to keep it more robust.

### *Cookies flow*


- Everytime we call the log-in command and send the credentials to the server, the server will
respond with `session cookies` that we'll use to execute operations like `enter_the_library`.
- The cookies array will be `free-ed` inside the `log-out` to make sure we don't hold on to 
cookies from the previous session.


# JWT Token


### *JWT Token structure*


- The JWT Token is held as a char array, dynamically allocated


### *JWT Token flow*


- After we've executed the `log-in` command and acquired the `session cookies` we're
able to execute privilged commands like `add_book` once we've entered the library by
executing the `enter_library` command. `The server` will respond with the `JWT Token`
that we'll use in the previously mentioned privileged commands to demonstrare our
authorization.


# JSON Parsing  -> Nlohmann Json


- Used `Nlohmann's JSON` library because I was familiar with it (kind of) and it
also was the one the homework's team recommended.

### Difficulties

- At the first iteration's of the homework, i mostly worked around with `(char *)`
representations of strings but then i switched to the `string` representation since
some of the methods inside this library were not `overloaded` for also using char pointers,
only strings.
- I think I spend more time in debugging `stdin` / `stdout` buffers and `string operations`
in contrast to the `networking` part. The main issues I faced were the *lifetimes* of the C++
string objects and how they interacted with the JSON library, bringing some huges problems when
passing `serialized` / `deserialized` objects around. For example I learned that you can't just do
something like this:

```
const char *some_func() {
    ...
    return book_json.dump().c_str();
}

The above code will return a dangling pointer, a more correct approach is this:

const char *some_func() {
    string book_serialized = book_json.dump();
    char *book_c_str = (char *)malloc(sizeof(char) * (book_serialized.length() + 1));
    memcpy(book_c_str, book_serialized.c_str(), book_serialized.length() + 1);

    return book_c_str;
}
```


### Other

- I modified the lab skeleton, I made a `generic compute` function that takes an additional
argument `packet_type` used to know how to handle the packet building depending on its type
(`GET`, `DELETE`, `POST`).
- Also, inside the previous mentioned function i removed the `query params` field since there
was no need of them in this assignment.
- I covered most of the `book fields`, `commands` input validity, but I still have
no idea what I should have done in the case of the checker's `nospace` test.
