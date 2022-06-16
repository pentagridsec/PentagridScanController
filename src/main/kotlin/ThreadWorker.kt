package ch.pentagrid.burpexts.pentagridscancontroller


class ThreadWorker(val burpExtender: BurpExtender): Thread() {

    override fun run() {
        while(true) {
            try {
                if(BurpExtender.unload)
                    return
                val candidate = BurpExtender.queuedCandidates.take() //blocks until queue is non-empty
                if(BurpExtender.unload)
                    return
                burpExtender.processHttpMessageOwnThread(candidate)
            }catch(e: InterruptedException){
                //Probably just means we called this thread's interrupt method to unload the extension
                if(BurpExtender.unload)
                    return
            }
        }
    }
}