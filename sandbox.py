from osc import Socket, Responder


class Mocket(Socket):
	@expose("/echo")
	def echo(self, message, source):
		print("echoing from %s %s"%source)
		message = "ECHO: "+message
		print(message)
		self(*source)["/echo"] << message

	@expose("/print")
	def print(self, message, source):
		print(message)
		print("from")
		print(source)

class bib(Responder):
	@expose("/zib")
	def bib(self, message, source):
		print("zib zib!")
		print(message)

a = Mocket(9090)
a.addTarget("/print",bib())
