import re
import shutil
import os
import time
D_MD = ".md"
MD_PRE = "---"
#add prefix to markdown
#add prefix to file name
#find the image ref, move the image, change ref to images/...

def move_img(path, content, dst_path = "../images"):
	ret = ""
	while True:
		r = re.search("!\\[([^\\[\\]]*)\\]\\(([a-zA-Z0-9_\\-\\.]+)\\)", content)
		if r == None:
			ret += content
			break
		img_name = r.group(2)
		beg = r.span()[0]
		end = r.span()[1]
		src = os.path.join(path, img_name)
		if not os.path.exists(src):
			print "\t[Error] The image %s does not exist" % (img_name)
			ret += content[:end]
			content = content[end:]
			continue
		print "\t[*] Moving image file %s" % (img_name)
		shutil.move(src, dst_path)
		ret += content[:beg]
		ret += "![%s](/images/%s)" % (r.group(1), img_name)
		content = content[end:]
	return ret

def add_md_pre(fpath, content, title):
	print "[*] Adding the prefix format to document %s" % (fpath)
	date = time.strftime("%Y-%m-%d %H:%M:%S", \
		time.gmtime(os.path.getmtime(fpath)))
	print type(title), type(date)
	pre = "---\nlayout: post\n" + \
			"title:  \"%s\"\n" + \
			"date:   %s +0000\n" + \
			"categories: jekyll update\n" + \
			"---\n\n"
	pre = pre % (title, date)
	content = pre + content
	f = open(fpath, "wb")
	f.write(content)
	f.close()
	return content

def add_file_pre(file, path):
	fpath = os.path.join(path, file)
	print "[*] Adding the prefix format to file name for %s" % (fpath)
	newname = time.strftime("%Y-%m-%d-", \
		time.gmtime(os.path.getmtime(fpath))) + file
	print "\t[*] Renaming %s to %s" % (file, newname)
	os.rename(file, newname)
	return newname

def process_md(file, path):
	fpath = os.path.join(path, file)
	# read the content
	f = open(fpath, "rb")
	content = f.read()
	f.close()
	if content[:len(MD_PRE)] != MD_PRE:
		content = add_md_pre(fpath, content, file[:-len(D_MD)])
	match = re.match( \
		"^[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-zA-Z0-9_\\-]+\\.md$", file)
	if match == None:
		file = add_file_pre(file, path)
		fpath = os.path.join(path, file)
	new_content = move_img(path, content)
	f = open(fpath, "wb")
	f.write(new_content)
	f.close()


def process_all_docs(path = "."):
	files = os.listdir(path)
	for file in files:
		# traverse all `.md` file
		if file[-len(D_MD):] == D_MD:
			print "[*] Processing file %s" % (file)
			process_md(file, path)

process_all_docs()


