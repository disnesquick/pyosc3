from osc import Socket


class Mocket(Socket):
	@expose("/echo")
	def echo(self, message, source):
		print("echoing from %s %s"%source)
		message = "ECHO: "+message
		self(*source)["/print"] << message
	@expose("/print")
	def print(self, message, source):
		print(message)
		print("from")
		print(source)
a = Mocket(9090)
