#pragma once

#include "pch.h"
#include <thread>
#include <chrono>
#include"../casbin/channel.h"
using namespace std;

void sender(Channel<int> c) {
                c.send(10);
            }

void receiver(Channel<int> c, bool* done) {
                int r = c.recv();
                Assert::AreEqual(10, r);
                *done = true;
            }            

void receive_buffered_chars(Channel<char> c)
            {
              char char_a(c.recv());
              char char_b(c.recv());
              char char_c(c.recv());

              Assert::AreEqual('A', char_a);
              Assert::AreEqual('B', char_b);
              Assert::AreEqual('C', char_c);
            }
            

void wait_sender(Channel<char> c,char ch,chrono::milliseconds duration) {
                this_thread::sleep_for(duration);
                c.send(ch);
            }
/*
void nested_channel(Channel<Channel<bool>> c) {
                Channel<bool> done(c.recv());
                done.send(true);
            }
            */
             
namespace test_util_channel
{
    TEST_CLASS(TestUtilChannel)
    {
        public:

            
            TEST_METHOD_INITIALIZE(TestSendReceive) {
                bool done = false;
                Channel<int> c = Channel<int>(0);
                std::thread f(sender, c);
                std::thread g(receiver,c, &done);
                f.join();
                g.join();

                Assert::AreEqual(done, true);
            }

            TEST_METHOD(TestBuffer) {
                Channel<char> c = Channel<char> (3);
                thread f(receive_buffered_chars, c);
                c.send('A');
                c.send('B');
                c.send('C');
                f.join();
            }
            
             TEST_METHOD(TestSelectRecv) {
                Channel<char> c1 = Channel<char> (1);
                Channel<char> c2 = Channel<char> (1);
                
                Select<char> s;
                char ch = 'S';
                int i = 0;

                Assert::AreEqual(i, 0);
                Assert::AreEqual(ch, 'S');
                thread f(wait_sender,c1, 'A', chrono::milliseconds(20));
                thread g(wait_sender,c2, 'B', chrono::milliseconds(50));


                s.recv(c1, ch, [&i]() { i = 10; });
                s.recv(c2, ch, [&i]() { i = 20; });
                s.run();

                Assert::AreEqual(i, 10);
                Assert::AreEqual(ch, 'A');

                f.join();
                g.join();
            }

             TEST_METHOD(TestSelectDefault) {
                Channel<char> c1 = Channel<char> (1);
                Channel<char> c2 = Channel<char> (1);
                
                Select<char> s;
                char ch = 'S';
                int i = 0;

                Assert::AreEqual(i, 0);
                Assert::AreEqual(ch, 'S');

                thread f(wait_sender, c1,'A', chrono::milliseconds(500));
                thread g(wait_sender, c2,'B', chrono::milliseconds(500));
                

                s.recv(c1, ch, [&i]() { i = 10; });
                s.recv(c2, ch, [&i]() { i = 20; });
                s.def([&i]() { i = 30; });
                s.run();

                Assert::AreEqual(i, 30);
                f.join();
                g.join();
            }
            
            /*
            TEST_METHOD(TestNested) {
                Channel<Channel<bool>> c = Channel<Channel<bool>> (0);
                Channel<bool> done = Channel<bool> (0);
                thread f(nested_channel, c);
                c.send(done);
                Assert::AreEqual(done.recv(),true);
            }*/
            
            
           
    };
}