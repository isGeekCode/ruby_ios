class Greeter
    def initialize(name = "world")
        @name = name
    end

    def say_hi
        puts "Hi #{@name}!"
    end
    def say_bye
        puts "Bye #{@name}, come back soon."
    end
end

greeter = Greeter.new("kim")
greeter.say_hi
greeter.say_bye

greeter2 = Greeter.new
greeter2.say_hi
greeter2.say_bye

greeter.@name