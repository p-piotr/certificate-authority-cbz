// NOTE: THIS TEST IS ENTIRELY AI-GENERATED
// I wanted to compare vairous methods of instantiating object
// but writing it all by hand would be tedious so I asked Chatbot instead
//this code won't be used anywhere in the actual program

#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <utility>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <utility>
#include <functional>
#include <sstream>

// Global counters for tracking operations
struct Stats {
    static inline int default_constructs = 0;
    static inline int copy_constructs = 0;
    static inline int move_constructs = 0;
    static inline int copy_assigns = 0;
    static inline int move_assigns = 0;
    
    static void reset() {
        default_constructs = 0;
        copy_constructs = 0;
        move_constructs = 0;
        copy_assigns = 0;
        move_assigns = 0;
    }
    
    static std::string toString() {
        std::ostringstream oss;
        oss << "D:" << std::setw(2) << default_constructs 
            << " CC:" << std::setw(2) << copy_constructs
            << " MC:" << std::setw(2) << move_constructs
            << " CA:" << std::setw(2) << copy_assigns
            << " MA:" << std::setw(2) << move_assigns;
        return oss.str();
    }
};

// Tracked string class that counts operations
class TrackedString {
    std::string data;
    
public:
    TrackedString() { 
        ++Stats::default_constructs;
    }
    
    TrackedString(const std::string& s) : data(s) { 
        ++Stats::default_constructs;
    }
    
    TrackedString(std::string&& s) : data(std::move(s)) { 
        ++Stats::default_constructs;
    }
    
    TrackedString(const TrackedString& other) : data(other.data) {
        ++Stats::copy_constructs;
    }
    
    TrackedString(TrackedString&& other) noexcept : data(std::move(other.data)) {
        ++Stats::move_constructs;
    }
    
    TrackedString& operator=(const TrackedString& other) {
        if (this !=& other) {
            data = other.data;
            ++Stats::copy_assigns;
        }
        return* this;
    }
    
    TrackedString& operator=(TrackedString&& other) noexcept {
        if (this !=& other) {
            data = std::move(other.data);
            ++Stats::move_assigns;
        }
        return* this;
    }
    
    const std::string& get() const { return data; }
};

// Different Container classes for each pattern
class ContainerByValue {
    TrackedString str;
public:
    ContainerByValue(TrackedString s) : str(s) {}
    const TrackedString& getStr() const { return str; }
};

class ContainerByValueMove {
    TrackedString str;
public:
    ContainerByValueMove(TrackedString s) : str(std::move(s)) {}
    const TrackedString& getStr() const { return str; }
};

class ContainerByConstRef {
    TrackedString str;
public:
    ContainerByConstRef(const TrackedString& s) : str(s) {}
    const TrackedString& getStr() const { return str; }
};

class ContainerByRvalueRef {
    TrackedString str;
public:
    ContainerByRvalueRef(TrackedString&& s) : str(s) {}
    const TrackedString& getStr() const { return str; }
};

class ContainerByRvalueRefMove {
    TrackedString str;
public:
    ContainerByRvalueRefMove(TrackedString&& s) : str(std::move(s)) {}
    const TrackedString& getStr() const { return str; }
};

void printHeader() {
    std::cout << std::string(110, '=') << "\n";
    std::cout << std::left << std::setw(55) << "Test Case" 
              << std::setw(40) << "Operations (D/CC/MC/CA/MA)" 
              << std::right << std::setw(15) << "Time (µs)\n";
    std::cout << std::string(110, '-') << "\n";
}

void printResult(const std::string& desc, long long time_us) {
    std::cout << std::left << std::setw(55) << desc 
              << std::setw(40) << Stats::toString()
              << std::right << std::setw(15) << time_us << "\n";
}

int main() {
    const int ITERATIONS = 10000;
    
    std::cout << "\n╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     C++ Object Instantiation Analysis - Single Objects        ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n\n";
    
    printHeader();
    
    // Test 1: Pass by value, lvalue source, no move in ctor
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        TrackedString source("test");
        ContainerByValue c(source);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("1. ByValue (no move in ctor) <- lvalue", duration);
    }
    
    // Test 2: Pass by value, lvalue source with std::move, no move in ctor
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        TrackedString source("test");
        ContainerByValue c(std::move(source));
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("2. ByValue (no move in ctor) <- std::move(lvalue)", duration);
    }
    
    // Test 3: Pass by value, rvalue source, no move in ctor
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        ContainerByValue c(TrackedString("test"));
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("3. ByValue (no move in ctor) <- rvalue", duration);
    }
    
    // Test 4: Pass by value with move in ctor, lvalue source
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        TrackedString source("test");
        ContainerByValueMove c(source);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("4. ByValue (+ move in ctor) <- lvalue", duration);
    }
    
    // Test 5: Pass by value with move in ctor, std::move at call
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        TrackedString source("test");
        ContainerByValueMove c(std::move(source));
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("5. ByValue (+ move in ctor) <- std::move(lvalue)", duration);
    }
    
    // Test 6: Pass by value with move in ctor, rvalue source
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        ContainerByValueMove c(TrackedString("test"));
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("6. ByValue (+ move in ctor) <- rvalue", duration);
    }
    
    // Test 7: Pass by const lvalue reference, lvalue source
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        TrackedString source("test");
        ContainerByConstRef c(source);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("7. ByConstRef <- lvalue", duration);
    }
    
    // Test 8: Pass by const lvalue reference, rvalue source (binds to const&)
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        ContainerByConstRef c(TrackedString("test"));
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("8. ByConstRef <- rvalue (binds to const&)", duration);
    }
    
    // Test 9: Pass by rvalue reference, no move in ctor, std::move at call
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        TrackedString source("test");
        ContainerByRvalueRef c(std::move(source));
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("9. ByRvalueRef (no move in ctor) <- std::move(lvalue)", duration);
    }
    
    // Test 10: Pass by rvalue reference, no move in ctor, rvalue source
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        ContainerByRvalueRef c(TrackedString("test"));
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("10. ByRvalueRef (no move in ctor) <- rvalue", duration);
    }
    
    // Test 11: Pass by rvalue reference with move in ctor, std::move at call
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        TrackedString source("test");
        ContainerByRvalueRefMove c(std::move(source));
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("11. ByRvalueRef (+ move in ctor) <- std::move(lvalue)", duration);
    }
    
    // Test 12: Pass by rvalue reference with move in ctor, rvalue source
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        ContainerByRvalueRefMove c(TrackedString("test"));
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("12. ByRvalueRef (+ move in ctor) <- rvalue", duration);
    }
    
    std::cout << std::string(110, '=') << "\n\n";
    
    // BENCHMARK SECTION
    std::cout << "\n╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║         Benchmark - " << ITERATIONS << " Objects per Test               ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n\n";
    
    printHeader();
    
    // Benchmark 1: Pass by value, no move in ctor, reused lvalue
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByValue> containers;
        TrackedString source("test");
        for (int i = 0; i < ITERATIONS; ++i) {
            containers.emplace_back(source);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B1. ByValue (no move) <- reused lvalue", duration);
    }
    
    // Benchmark 2: Pass by value, no move in ctor, std::move(lvalue)
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByValue> containers;
        for (int i = 0; i < ITERATIONS; ++i) {
            TrackedString source("test");
            containers.emplace_back(std::move(source));
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B2. ByValue (no move) <- std::move(lvalue)", duration);
    }
    
    // Benchmark 3: Pass by value, no move in ctor, rvalue
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByValue> containers;
        for (int i = 0; i < ITERATIONS; ++i) {
            containers.emplace_back(TrackedString("test"));
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B3. ByValue (no move) <- rvalue", duration);
    }
    
    // Benchmark 4: Pass by value with move in ctor, reused lvalue
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByValueMove> containers;
        TrackedString source("test");
        for (int i = 0; i < ITERATIONS; ++i) {
            containers.emplace_back(source);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B4. ByValue (+ move) <- reused lvalue", duration);
    }
    
    // Benchmark 5: Pass by value with move in ctor, std::move(lvalue)
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByValueMove> containers;
        for (int i = 0; i < ITERATIONS; ++i) {
            TrackedString source("test");
            containers.emplace_back(std::move(source));
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B5. ByValue (+ move) <- std::move(lvalue)", duration);
    }
    
    // Benchmark 6: Pass by value with move in ctor, rvalue
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByValueMove> containers;
        for (int i = 0; i < ITERATIONS; ++i) {
            containers.emplace_back(TrackedString("test"));
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B6. ByValue (+ move) <- rvalue", duration);
    }
    
    // Benchmark 7: Pass by const ref, reused lvalue
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByConstRef> containers;
        TrackedString source("test");
        for (int i = 0; i < ITERATIONS; ++i) {
            containers.emplace_back(source);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B7. ByConstRef <- reused lvalue", duration);
    }
    
    // Benchmark 8: Pass by const ref, rvalue
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByConstRef> containers;
        for (int i = 0; i < ITERATIONS; ++i) {
            containers.emplace_back(TrackedString("test"));
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B8. ByConstRef <- rvalue", duration);
    }
    
    // Benchmark 9: Pass by rvalue ref, no move in ctor, std::move(lvalue)
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByRvalueRef> containers;
        for (int i = 0; i < ITERATIONS; ++i) {
            TrackedString source("test");
            containers.emplace_back(std::move(source));
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B9. ByRvalueRef (no move) <- std::move(lvalue)", duration);
    }
    
    // Benchmark 10: Pass by rvalue ref, no move in ctor, rvalue
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByRvalueRef> containers;
        for (int i = 0; i < ITERATIONS; ++i) {
            containers.emplace_back(TrackedString("test"));
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B10. ByRvalueRef (no move) <- rvalue", duration);
    }
    
    // Benchmark 11: Pass by rvalue ref with move in ctor, std::move(lvalue)
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByRvalueRefMove> containers;
        for (int i = 0; i < ITERATIONS; ++i) {
            TrackedString source("test");
            containers.emplace_back(std::move(source));
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B11. ByRvalueRef (+ move) <- std::move(lvalue)", duration);
    }
    
    // Benchmark 12: Pass by rvalue ref with move in ctor, rvalue
    {
        Stats::reset();
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<ContainerByRvalueRefMove> containers;
        for (int i = 0; i < ITERATIONS; ++i) {
            containers.emplace_back(TrackedString("test"));
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        printResult("B12. ByRvalueRef (+ move) <- rvalue", duration);
    }
    
    std::cout << std::string(110, '=') << "\n\n";
    
    std::cout << "╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                         Key Insights                          ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n\n";
    
    std::cout << "Legend:\n";
    std::cout << "  • D:  Default constructions (creating TrackedString from string literal)\n";
    std::cout << "  • CC: Copy constructor calls\n";
    std::cout << "  • MC: Move constructor calls\n";
    std::cout << "  • CA: Copy assignment calls\n";
    std::cout << "  • MA: Move assignment calls\n\n";
    
    std::cout << "Best Practices:\n";
    std::cout << "  1. Pass by value + std::move in ctor is optimal for rvalues\n";
    std::cout << "  2. Pass by const& is best for reused lvalues (avoids param copy)\n";
    std::cout << "  3. Pass by & & + std::move in ctor is optimal for temporary objects\n";
    std::cout << "  4. Without std::move in ctor, rvalue ref parameter behaves like lvalue\n";
    std::cout << "  5. std::move at call site converts lvalue to rvalue, enabling moves\n";
    std::cout << "  6. Consider using forwarding references (T&&) with std::forward for templates\n\n";
    
    return 0;
}
