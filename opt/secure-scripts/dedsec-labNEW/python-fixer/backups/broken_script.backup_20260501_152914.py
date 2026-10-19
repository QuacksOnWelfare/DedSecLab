import os,sys
import   math
from datetime import datetime, timedelta


def   greet(name ):
 print("Hello, "+name )


def calculate (x,y):
    result=x+y
    return result


def broken_function():
    print("This line is fine")
      print("This line has bad indent")
    if True:
     print("bad spacing")
    else:
            print("too much indent")


def loop_test():
 for i in range(5):
        print(i)
      print("wrong indent again")


def syntax_error():
    print("Missing quote)


def unused_function( ):
    x=10
    y=20
    z=30


def messy_logic(a,b):
    if(a> b):
        print("A bigger")
    else:
     print("B bigger")
    if a==b: print("equal")    


def main( ):
    name = input("Enter name:")
    greet(name)
    
    total=calculate(5,10)
    print("Total:",total)
    
    broken_function()
    loop_test()
    messy_logic(10,5)

    now=datetime.now( )
    print("Time:", now )


if __name__=="__main__":
 main()
