#include "pch.h"
#include "channel.h"

template <class T>
Internal_Channel<T>::Internal_Channel<T>(int bufsize) {
  qcount = 0;
  dataqsiz = bufsize;
  closed = false;
}

template <class T>
Internal_Channel<T>::Internal_Channel<T>(Internal_Channel<T>& ic) {
  qcount=ic->qcount;
  dataqsiz=ic->dataqsiz;
  buf = move(ic->buf);
  recvq = move(ic->recvq);
  sendq = move(ic->sendq);
}

template <class T>
T Internal_Channel<T>::recv(void) {
  std::unique_lock <std::mutex> lck(lock);
  cout << "receive" << endl;
  T ans = T();

  if (closed == true && qcount == 0) {
    cout << "closed" << endl;
    return ans;
  }

  if (!sendq.empty()) {
    cout << "sendq not empty" << endl;
    shared_ptr<Sudog<T>> sg = sendq.front();
    cout << "pop sendq:" << sg->elem << endl;
    sendq.pop_front();
    if (dataqsiz == 0) {
      ans = sg->elem;
    }
    else {
      ans = buf.front();
      buf.pop_front();
      buf.push_back(sg->elem);
    }
    sg->done = true;
    lck.unlock();
    sg->cv->notify_one();
    return ans;
  }

  if (qcount > 0) {
    ans = buf.front();
    buf.pop_front();
    qcount--;
    return ans;
  }

  cout << "create recv sudog" << endl;
  shared_ptr<Sudog<T>> mysg = shared_ptr<Sudog<T>>(new Sudog<T>());
  mysg->c = this;
  mysg->isSelect = NONE;
  recvq.push_back(mysg);
  mysg->cv->wait(lck);
  ans = move(mysg->elem);
  return ans;
}

template <class T>
void Internal_Channel<T>::recv(T &elem) {

}

template <class T>
void Internal_Channel<T>::send(const T& elem) {
    std::unique_lock <std::mutex> lck(lock);
    cout << "lsend" << elem << endl;
    if (!recvq.empty()) {
      cout << "recvq not empty" << endl;
      shared_ptr<Sudog<T>> mysg = recvq.front();
      recvq.pop_front();
      mysg->elem = elem;
      cout << "recvq done" << endl;
      mysg->done = true;
      lck.unlock();
      mysg->cv->notify_one();
      return;
    }

    if (qcount < dataqsiz) {
      cout << "send to buf:" << endl;
      buf.push_back(elem);
      qcount++;
      return;
    }
    cout << "create send sudog" << endl;
    shared_ptr<Sudog<T>> mysg = shared_ptr<Sudog<T>>(new Sudog<T>());
    mysg->c = this;
    mysg->isSelect = NONE;
    mysg->elem = elem;
    sendq.push_back(mysg);
    mysg->cv->wait(lck);
}

template <class T>
void Internal_Channel<T>::send(T&& elem) {
    std::unique_lock <std::mutex> lck(lock);
    cout << "rsend" << elem << endl;
    if (!recvq.empty()) {
      cout << "recvq not empty" << endl;
      shared_ptr<Sudog<T>> mysg = recvq.front();
      recvq.pop_front();
      cout << "pop recvq:" << mysg->elem << endl;
      mysg->elem = move(elem);
      cout << "recvq done" << endl;
      mysg->done = true;
      lck.unlock();
      mysg->cv->notify_one();
      return;
    }

    if (qcount < dataqsiz) {
      cout << "send to buf:" << endl;
      buf.push_back(elem);
      qcount++;
      return;
    }
    cout << "create send sudog" << endl;
    shared_ptr<Sudog<T>> mysg = shared_ptr<Sudog<T>>(new Sudog<T>());
    mysg->c = this;
    mysg->isSelect = NONE;
    mysg->elem = move(elem);
    cout << "push_back send sudog:" << mysg->elem << endl;
    sendq.push_back(mysg);
    mysg->cv->wait(lck);
}

template <class T>
bool Internal_Channel<T>::try_send(void) {
  if (!recvq.empty()||qcount < dataqsiz) {
    return true;
  }

  return false;
}

template <class T>
bool Internal_Channel<T>::try_receive() {
   if (closed == true && qcount == 0) {
     return false;
   }

   if (!sendq.empty()|| qcount>0) {
     return true;
   }

   return false;
}


template <class T>
void Internal_Channel<T>::close(void) {

}

template <class T>
Sudog<T>::Sudog<T>() {
    cv = shared_ptr<condition_variable>(new condition_variable());
    done = false;
}

template <class T>
Sudog<T>::Sudog<T>(Sudog<T>& sdg) {

}

template <class T>
shared_ptr<Sudog<T>> Sudog<T>::getsudog(void) {
  shared_ptr<Sudog<T>> ptr = shared_ptr<Sudog<T>>(new Sudog<T>());
  return ptr;
}

template <class T>
Channel<T>::Channel<T>(){
  ptr = shared_ptr<Internal_Channel<T>>(new Internal_Channel<T>(0));
}

template <class T>
Channel<T>::Channel<T>(const int& bufsize){
  ptr = shared_ptr<Internal_Channel<T>>(new Internal_Channel<T>(bufsize));
}

template <class T>
T Channel<T>::recv(void) {
  return ptr->recv();
}

template <class T> void Channel<T>::recv(T &elem) {
  return ptr->recv(elem);
}

template <class T>
void Channel<T>::send(const T& elem) {
  ptr->send(elem);
}

template <class T>
void Channel<T>::send(T&& elem){
  ptr->send(move(elem));
}

template <class T>
bool Channel<T>::try_send() {
   return ptr->try_send();
}

template <class T>
bool Channel<T>::try_receive() {
   return ptr->try_receive();
}

template <class T>
void Channel<T>::close(void) {
  ptr->close();
}

template <class T>
SCase<T>::SCase<T>() {

 }

template <class T>
SCase<T>::SCase<T>(const Channel<T>& c, function<void(void)> f) {
  this->c = c.ptr;
  this->f = f;
}

template <class T>
Internal_Select<T>::Internal_Select<T>() {
   cv = shared_ptr<condition_variable>(new condition_variable());
   running = false;
   defed = false;
}

template <class T>
void Internal_Select<T>::send(const Channel<T>& c, T&& elem, function<void(void)> f) {
  shared_ptr<SCase_Send<T>> sc = shared_ptr<SCase_Send<T>>(new SCase_Send<T>(c,move(elem),f));
  cases.push_back(sc);
}

template <class T>
void Internal_Select<T>::send(const Channel<T>& c, const T& elem, function<void(void)> f) {
  shared_ptr<SCase_Send<T>> sc = shared_ptr<SCase_Send<T>>(new SCase_Send<T>(c,elem,f));
  cases.push_back(sc);
}

template <class T>
void Internal_Select<T>::recv(const Channel<T>& c, T& elem, function<void(void)> f) {
  cout << "Internal_sc recv" << endl;
  shared_ptr<SCase_Recv<T>> sc = shared_ptr<SCase_Recv<T>>(new SCase_Recv<T>(c,elem,f));
  cases.push_back(sc);
}

template <class T>
void Internal_Select<T>::def(function<void(void)> f) {
  if (defed)
    return;
  defed = true;
  shared_ptr<SCase_Def<T>> sc = shared_ptr<SCase_Def<T>>(new SCase_Def<T>(f));
  def_case = sc;
}

template <class T>
void Internal_Select<T>::run() {
  std::unique_lock <std::mutex> lck(lock);
  cout << "sc run!" << endl;
  int case_size = cases.size();
  bool flag = false;
  deque<shared_ptr<Sudog<T>>> mysgs;

  
  for (int i = 0; i < case_size; i++) {
    cases[i]->c->lock.lock();
    cout << "lock case" << i << endl;
  }
  

  for (int i = 0; i < case_size; i++) {
    shared_ptr<SCase<T>> scase = cases[i];
    if (scase->ct == RECEIVE) {
      if (scase->c->try_receive()) {
        flag = true;
        scase->recv();
        scase->execute();
      } else {
        cout << "create recv_sudog in sc" << endl;
        shared_ptr<Sudog<T>> mysg = shared_ptr<Sudog<T>>(new Sudog<T>());
        mysg->cv = this->cv;
        mysg->c = scase->c.get();
        mysg->isSelect = RECEIVE;
        scase->c->recvq.push_back(mysg);
        mysgs.push_back(mysg);
      }
    }
    else if (scase->ct == SEND) {
      if (scase->c->try_send()) {
        flag = true;
        scase->send();
        scase->execute();
      } else {
        shared_ptr<Sudog<T>> mysg = shared_ptr<Sudog<T>>(new Sudog<T>());
        mysg->cv = this->cv;
        mysg->c = scase->c.get();
        mysg->isSelect = SEND;
        mysg->elem = move(static_cast<SCase_Send<T> *>(scase.get())->elem);
        scase->c->recvq.push_back(mysg);
        mysgs.push_back(mysg);
      }
    }
  }

  for (int i = 0; i < case_size; i++) {
      cases[i]->c->lock.unlock();
      cout << "unlock case i" << i << endl;
    }

  if (!defed) { 
    cv->wait(lck);
    //cout << "waited!" << endl;
  } else {
    def_case->execute();
  }

  
  for (int i = 0; i < case_size; i++) {
    cases[i]->c->lock.lock();
    //cout << "lock case" << i << endl;
  }
  
  bool selected = false;
  while (!mysgs.empty()) {
    shared_ptr <SCase<T>> scase = cases.front();
    shared_ptr <Sudog<T>> mysg = mysgs.front();
    mysgs.pop_front();
    cases.pop_front();
    if (mysg->isSelect == RECEIVE) {
        cout<< "check receive "<<endl;
        if (mysg->done&&!selected) {
          cout << "done" << endl;
          selected = true;
          static_cast<SCase_Recv<T> *>(scase.get())->elem = move(mysg->elem);
          scase->execute();
        }
        else {
          cout << "not done" << endl;
          shared_ptr<Sudog<T>> next = mysg->next;
          shared_ptr<Sudog<T>> prev = mysg->prev;
          if (prev.get() == NULL) {
            if (next.get() == NULL) {
                scase->c->recvq.head.reset();
                scase->c->recvq.rear.reset();
            }
            else {
              mysg->next.reset();
              next->prev.reset();
              scase->c->recvq.head=next;
            }
          } else {
            if (next.get() == NULL) {
              mysg->prev.reset();
              prev->next.reset();
              scase->c->recvq.rear=prev;
            }
            else {
              mysg->prev.reset();
              mysg->next.reset();
              prev->next = next;
              next->prev = prev;
            }
          }
          scase->c->recvq.size--;
        }
    }
    else {
        cout<< "check send "<<endl;
        if (mysg->done&&!selected) {
            selected = true;
          cout << "done" << endl;
          scase->execute();
        }
        else {
          cout << "not done" << endl;
          shared_ptr<Sudog<T>> next = mysg->next;
          shared_ptr<Sudog<T>> prev = mysg->prev;
          if (prev.get() == NULL) {
            if (next.get() == NULL) {
                scase->c->sendq.head.reset();
                scase->c->sendq.rear.reset();
            }
            else {
              mysg->next.reset();
              next->prev.reset();
              scase->c->sendq.head=next;
            }
          } else {
            if (next.get() == NULL) {
              mysg->prev.reset();
              prev->next.reset();
              scase->c->sendq.rear=prev;
            }
            else {
              mysg->prev.reset();
              mysg->next.reset();
              prev->next = next;
              next->prev = prev;
            }
          }
          scase->c->recvq.size--;
        }
    }
    scase->c->lock.unlock();
    cout << "unlock case" <<endl;
  }
  return;
}

template <class T> 
Sudog_List<T>::Sudog_List<T>() {
    int size=0;
}

template <class T> 
Sudog_List<T>::~Sudog_List() {
    shared_ptr<Sudog<T>> cur = this->head;
    shared_ptr<Sudog<T>> nxt;
    while (cur.get() != NULL) {
      nxt = cur->next;
      cur->prev.reset();
      cur->next.reset();
      cur = nxt;
    }
}

template <class T> 
bool Sudog_List<T>::empty() {
    return size==0;
}

template <class T> 
shared_ptr<Sudog<T>> Sudog_List<T>::front() {
    return head;
}

template <class T> 
void Sudog_List<T>::pop_back() {
  if (size > 0) {
    shared_ptr<Sudog<T>> prev = rear->prev;
    if (size > 1)
      prev->next = shared_ptr<Sudog<T>>();
    rear->prev = shared_ptr<Sudog<T>>();
    rear = prev;
    size--;
  }
}

template <class T> 
void Sudog_List<T>::pop_front() {
   if (size > 0) {
     shared_ptr<Sudog<T>> next = head->next;
     if (size > 1)
       next->prev.reset();
     head->next.reset();
     head = next;
     size--;
   }
}

template <class T> 
void Sudog_List<T>::push_back(const shared_ptr<Sudog<T>>& sg) {
    if (size == 0) {
      head = sg;
      rear = sg;
    } else {
      sg->prev = rear;
      rear->next = sg;
      rear = sg;
    }
    size++;
}

template <class T> 
SCase_Send<T>::SCase_Send<T>(const Channel<T>& c, T&& elem, function<void(void)> f) {
    this->ct = SEND;
    this->c = c;
    this->elem = move(elem);
    this->f = f;
}

template <class T> 
SCase_Send<T>::SCase_Send<T>(const Channel<T>& c, const T& elem, function<void(void)> f) {
    this->ct = SEND;
    this->c = c;
    this->elem = elem;
    this->f = f;
}

template <class T> 
void SCase_Send<T>::execute() {
    this->f();
}

template <class T> 
void SCase_Send<T>::recv() {
    cout<<"SCase_Send can't recv"<<endl;
}

template <class T> 
void SCase_Send<T>::send() {
    cout << "SCase_send:" << elem << endl;
    shared_ptr<Internal_Channel<T>> c = this->c;
    if (c->recvq.empty()) {
      cout << "recvq not empty" << endl;
      shared_ptr<Sudog<T>> mysg = c->recvq.front();
      c->recvq.pop_front();
      mysg->elem = elem;
      mysg->done = true;
      mysg->cv->notify_one();
      return;
    }

    if (c->qcount < c->dataqsiz) {
      cout << "send to buf" << endl;
      c->buf.push_back(elem);
      c->qcount++;
      return;
    }
}

template <class T> 
SCase_Recv<T>::SCase_Recv<T>(const Channel<T>& c, T& elem, function<void(void)> f):SCase<T>(c,f),elem(elem) {
    cout << "Create SCase Recv" << endl;
    this->ct = RECEIVE;
}

template <class T> 
void SCase_Recv<T>::execute() {
    this->f();
}

template <class T> 
void SCase_Recv<T>::recv() {
  cout << "SCase_Recv: " << endl;
  shared_ptr<Internal_Channel<T>> c = this->c;
  if (!c->sendq.empty()) {
    cout << "sendq not empty" << endl;
    shared_ptr<Sudog<T>> sg = c->sendq.front();
    c->sendq.pop_front();
    if (c->dataqsiz == 0) {
      elem = sg->elem;
    }
    else {
      elem = c->buf.front();
      c->buf.pop_front();
      c->buf.push_back(sg->elem);
    }
    sg->done = true;
    sg->cv->notify_one();
    return;
  }

  if (c->qcount > 0) {
    elem = c->buf.front();
    c->buf.pop_front();
    c->qcount--;
  }
}

template <class T> 
void SCase_Recv<T>::send() {
    cout<<"SCase_Recv can't send"<<endl;
}

template <class T> 
SCase_Def<T>::SCase_Def(function<void(void)> f) {
    this->ct = DEFAULT;
    this->f = f;
}

template <class T> 
void SCase_Def<T>::execute() {
    this->f();
}

template <class T> 
void SCase_Def<T>::recv() {
    cout<<"SCase_Def can't send"<<endl;
}

template <class T> 
void SCase_Def<T>::send() {
    cout<<"SCase_Def can't send"<<endl;
}

template <class T> 
Select<T>::Select<T>() {
  ptr = shared_ptr<Internal_Select<T>>(new Internal_Select<T>());
}

template <class T> 
void Select<T>::send(const Channel<T>& c, T&& elem, function<void(void)> f) {
  ptr->send(c, move(elem), f);
}

template <class T> 
void Select<T>::send(const Channel<T>& c, const T& elem, function<void(void)> f) {
    ptr->send(c, elem, f);
}

template <class T> 
void Select<T>::recv(const Channel<T>& c, T& elem, function<void(void)> f) {
    ptr->recv(c, elem, f);
}

template <class T> 
void Select<T>::def(function<void(void)> f) {
    ptr->def(f);
}

template <class T> 
void Select<T>::run() {
    ptr->run();
}

void f1(Channel<int> c) {
                c.send(10);
            }

void f2(Channel<int> c, bool* done) {
                int r = c.recv();
                *done = true;
            }

void f3(Channel<char> c)
            {
              char char_a(c.recv());
              char char_b(c.recv());
              char char_c(c.recv());

            }

/*
void f4(Channel<Channel<bool>> c) {
                Channel<bool> done(c.recv());
                done.send(true);
            }*/
            
            

void f5(Channel<char> c)
            {
                Channel<char> c1 = Channel<char>(10);
                Channel<bool> c2 = Channel<bool>(10);
                Channel<int> c3 = Channel<int>(10);
                c1.send('A');
                 c2.send(true);
                  c3.send(false);
                 c1.recv();
                  c2.recv();
                  c3.recv();

            }
            

void f6(Channel<char> c,char ch,chrono::milliseconds duration) {
                this_thread::sleep_for(duration);
                c.send(ch);
            }

void f7(Channel<char> c,char ch,chrono::milliseconds duration) {
                this_thread::sleep_for(duration);
                c.send(ch);
            }

void f8()
 {
                Channel<char> c1 = Channel<char> (1);
                Channel<char> c2 = Channel<char> (1);
                
                Select<char> s;
                char ch = 'S';
                int i = 0;


                thread f(f7,c1, 'A', chrono::milliseconds(20));
                thread g(f7,c2, 'B', chrono::milliseconds(50));
                f.join();
                g.join();

                s.recv(c1, ch, [&i]() { i = 10; });
                s.recv(c2, ch, [&i]() { i = 20; });
                s.run();

}

void f9() {
    Channel<char> c1 = Channel<char> (1);
                Channel<char> c2 = Channel<char> (1);
                
                Select<char> s;
                char ch = 'S';
                int i = 0;

               

                thread f(f7, c1,'A', chrono::milliseconds(20));
                thread g(f7, c2,'B', chrono::milliseconds(50));
                f.join();
                g.join();

                s.recv(c1, ch, [&i]() { i = 10; });
                s.recv(c2, ch, [&i]() { i = 20; });
                s.def([&i]() { i = 30; });
                s.run();

}




template <class T>
Ticker<T>::Ticker(chrono::duration<int, milli> duration) {
    this->tickerGuard = TickerGuard<T>();
    this->duration=duration;
    this->signal=signal;
    this->c = Channel<T>(1);
    tickerGuard.startTimer(this);
}

template <class T>
Ticker<T>::Ticker(chrono::duration<int, milli> duration, T signal) {
    this->tickerGuard = TickerGuard<T>();
    tickerGuard.startTimer(this);
    this->duration=duration;
    this->signal=signal;
    this->c = Channel<T>(1);
    tickerGuard.startTimer(this);
}

template <class T>
Ticker<T>::~Ticker() {
    stop();
}

template <class T>
void Ticker<T>::setSignal(T signal) {
    this->signal = signal;
}

template <class T>
void Ticker<T>::stop() {
    tickerGuard.stopTimer();
}

template <class T>
void Ticker<T>::send() {

}

template <class T>
TickerGuard<T>::TickerGuard() {

}

template <class T>
void tickerFunc(Ticker<T>* ticker) {
    try {
        while (ticker!=NULL) {
        Select<T> sc = Select<T>();
        sc.send(ticker->c, ticker->signal, []() {});
        sc.def([]() {});
        sc.run();
        this_thread::sleep_for(ticker->duration);
        }
    }
    catch (exception &e){

    }
    return;
}

template <class T>
void TickerGuard<T>::startTimer(Ticker<T>* ticker) {
    if (ticker != NULL) {
        this->ticker = ticker;
        thread t(tickerFunc,ticker);
        t.detach();
        this->p_thread = &t;
    }
}

template <class T>
void TickerGuard<T>::stopTimer() {
    try {
        if (ticker != NULL && p_thread!=NULL) {
            p_thread->~thread();
        }
    }
    catch (exception& e) {

    }
   
    return;
}