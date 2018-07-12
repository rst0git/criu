import os

def create_fds():
	(fd1, fd2) = os.pipe()
	return (os.fdopen(fd2, "wb"), os.fdopen(fd1, "rb"))

def filename(pipef):
	return 'pipe:[%d]' % os.fstat(pipef.fileno()).st_ino

def dump_opts(sockf):
	return [ ]
