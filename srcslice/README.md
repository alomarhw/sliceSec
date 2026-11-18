# srcSlice
Lightweight tool for slicing

To build srcSlice:

1. Clone the repository with 'git clone --recursive' into the desired directory. Make sure you include the --recursive as srcSlice includes a submodule that must also be cloned.

2. Outside of the cloned directory, create a new directory for the build.  (This guide assumes the new directory is at the same directory tree level as the cloned directory)

3. Enter the new directory (not the cloned one) and type 'cmake ../{cloned directory}'

4. After cmake runs, simply type 'make' and all files should be built.  

5. Once everything is built, go into the 'bin' folder and that's where the executable will be.

## Usage

Slice a whole project. srcSlice is forward and whole-system, so give it an archive rather than a single function:

    srcml --position <project-dir> -o project.xml
    srcSlice project.xml > slices.csv

Each output line is the slice profile of one variable:

    file,function,variable,def{lines},use{lines},dvars{variables},pointers{variables},cfuncs{function{argument position}}

An entry `f{k}` in `cfuncs` means the variable is passed as the k-th argument of `f`. Interprocedural slices are
built by following it into the slice of `f`'s k-th parameter.

`srcSlice --help` and `srcSlice --version` print usage and version. Unreadable or malformed input exits with status 1.

## Languages

C, C++, C#, Java and Python (srcML 1.1.0 or later). The Python support covers:
- keyword arguments, mapped to the named parameter of a callee defined in the archive;
- method calls `obj.m(x)`, where the receiver fills `self`/`cls`;
- `for ... in`, comprehensions, `with ... as` and tuple targets;
- augmented assignment, annotations, decorators, nested functions, lambdas, `raise`/`yield`, and the
  variables and simple calls inside f-strings.
