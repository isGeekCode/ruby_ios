class Book
    attr_accessor :title, :author, :price
    def initialize(title, author, price)
      @title = title
      @author = author
      @price = price
    end
end

books = Array.new
books << Book.new("Programming Ruby", "데이브 토마스", 54900)
books << Book.new("The Ruby Way", "할 풀턴", 60000)
books << Book.new("Learn to Program", "크리스 파인", 27400)

books.each {|b| puts b.title + " (" + b.author + "): " + b.price.to_s + "원"}

puts "책의 가격은 총 " + books.inject(0) {|sum, b| sum += b.price}.to_s + "원 입니다!"

# ruby test4.rb
# Programming Ruby (데이브 토마스): 54900원
# The Ruby Way (할 풀턴): 60000원
# Learn to Program (크리스 파인): 27400원
# 책의 가격은 총 142300원 입니다!