class Person
    def initialize(name)
        @name = name
    end

    def run
       puts "#{@name}이/가 달립니다!"
    end

    def drink
       puts "#{@name}이/가 물을 마십니다!"
    end
end

person = Person.new("sunny")
person.run
person.drink