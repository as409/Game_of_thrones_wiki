import handler

class WikiPage(handler.Handler):
	"""
	Handler for displaying the wiki page.
	"""
	def get(self, path):
		page = self.version_check(path)

		if page:
			self.render("wiki_page.html", page=page, path=path)
		else:
			self.redirect("/_edit" + path)
