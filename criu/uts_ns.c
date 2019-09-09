#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <string.h>
#include <sched.h>

#include "util.h"
#include "namespaces.h"
#include "sysctl.h"
#include "uts_ns.h"
#include "img-remote.h"
#include "cr_options.h"

#include "protobuf.h"
#include "images/utsns.pb-c.h"

int dump_uts_ns(int ns_id)
{
	int ret;
	struct utsname ubuf;
	UtsnsEntry ue = UTSNS_ENTRY__INIT;

	ret = uname(&ubuf);
	if (ret < 0) {
		pr_perror("Error calling uname");
		goto err;
	}

	ue.nodename = ubuf.nodename;
	ue.domainname = ubuf.domainname;

	if (opts.remote) {
		ret = remote_send_entry(&ue, PB_UTSNS, CR_FD_UTSNS, ns_id);
	} else {
		struct cr_img *img = open_image(CR_FD_UTSNS, O_DUMP, ns_id);
		if (img) {
			ret = pb_write_one(img, &ue, PB_UTSNS);
			close_image(img);
		}
	}
err:
	return ret;
}

int prepare_utsns(int pid)
{
	int ret = -1;
	struct cr_img *img = NULL;
	UtsnsEntry *ue;
	struct sysctl_req req[] = {
		{ "kernel/hostname" },
		{ "kernel/domainname" },
	};

	if (opts.remote) {
		ret = remote_read_one(&ue, PB_UTSNS, CR_FD_UTSNS, pid);
	} else {
		img = open_image(CR_FD_UTSNS, O_RSTR, pid);
		if (img)
			ret = pb_read_one(img, &ue, PB_UTSNS);
	}

	if (ret < 0)
		goto out;

	req[0].arg = ue->nodename;
	req[0].type = CTL_STR(strlen(ue->nodename));
	req[1].arg = ue->domainname;
	req[1].type = CTL_STR(strlen(ue->domainname));

	ret = sysctl_op(req, ARRAY_SIZE(req), CTL_WRITE, CLONE_NEWUTS);
	utsns_entry__free_unpacked(ue, NULL);
out:
	close_image(img);
	return ret;
}

struct ns_desc uts_ns_desc = NS_DESC_ENTRY(CLONE_NEWUTS, "uts");
