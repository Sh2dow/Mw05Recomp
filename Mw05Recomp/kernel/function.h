#pragma once

#include <cpu/ppc_context.h>
#include <array>
#include <tuple>
#include <type_traits>
#include <utility>
#include "xbox.h"
#include "memory.h"
#include "trace.h"
extern "C" uint32_t Mw05GetHostDefaultVdIsrMagic();
void Mw05AutoVideoInitIfNeeded();
void Mw05StartVblankPumpOnce();

// --- Detect "variadic function pointer" types like R(*)(Args..., ...)
template <typename T>
struct is_variadic_fp : std::false_type {};

template <typename R, typename... Args>
struct is_variadic_fp<R(*)(Args..., ...)> : std::true_type {};

// --- Basic function traits for raw function pointers
template <typename T>
struct function_traits;

template <typename R, typename... Args>
struct function_traits<R(*)(Args...)>
{
    using return_type = R;
    using args_tuple = std::tuple<Args...>;
    using args_tuple_decay = std::tuple<std::decay_t<Args>...>;
    static constexpr size_t arity = sizeof...(Args);
};

// Helper to materialize an args tuple value (decayed) for a function pointer
template <typename R, typename... T>
constexpr std::tuple<std::decay_t<T>...> function_args(R(*)(T...)) noexcept
{
    return std::tuple<std::decay_t<T>...>{};
}

// Detect PPC recompiled function pointers: void(PPCContext&, uint8_t*)
template<typename T>
struct is_ppc_func_ptr : std::false_type {};

template<typename R, typename A0, typename A1>
struct is_ppc_func_ptr<R(*)(A0, A1)> : std::bool_constant<
    std::is_same_v<std::remove_reference_t<A0>, PPCContext> &&
    std::is_same_v<std::remove_cv_t<std::remove_reference_t<A1>>, uint8_t*>
> {};

template<auto V>
static constexpr decltype(V) constant_v = V;

template<typename T>
static constexpr bool is_precise_v = std::is_same_v<T, float> || std::is_same_v<T, double>;

template<auto Func>
struct arg_count_t
{
    static constexpr size_t value = function_traits<decltype(Func)>::arity;
};

template<typename TCallable, int I = 0, typename ...TArgs>
std::enable_if_t<(I >= sizeof...(TArgs)), void> _tuple_for(std::tuple<TArgs...>&, const TCallable& callable) noexcept
{

}

template<typename TCallable, int I = 0, typename ...TArgs>
std::enable_if_t<(I < sizeof...(TArgs)), void> _tuple_for(std::tuple<TArgs...>& tpl, const TCallable& callable) noexcept
{
    callable(std::get<I>(tpl), I);

    _tuple_for<TCallable, I + 1>(tpl, callable);
}

struct ArgTranslator
{
    constexpr static uint64_t GetIntegerArgumentValue(const PPCContext& ctx, uint8_t* base, size_t arg) noexcept
    {
        if (arg <= 7)
        {
            switch (arg)
            {
                case 0: return ctx.r3.u32;
                case 1: return ctx.r4.u32;
                case 2: return ctx.r5.u32;
                case 3: return ctx.r6.u32;
                case 4: return ctx.r7.u32;
                case 5: return ctx.r8.u32;
                case 6: return ctx.r9.u32;
                case 7: return ctx.r10.u32;
                default: break;
            }
        }

        // Fallback to stack for arguments beyond GPRs (r3..r10).
        // Be defensive early in boot: validate the guest stack address before dereferencing.
        const size_t offset = ctx.r1.u32 + 0x54 + ((arg - 8) * 8);
        // First page is intentionally PAGE_NOACCESS; also ensure within guest memory.
        if (offset < 4096 || (offset + sizeof(be<uint32_t>)) > PPC_MEMORY_SIZE)
        {
            return 0; // Avoid host AV; caller typically treats missing extra args as zero.
        }

        return *reinterpret_cast<be<uint32_t>*>(base + offset);
    }

    static double GetPrecisionArgumentValue(const PPCContext& ctx, uint8_t* base, size_t arg) noexcept
    {
        switch (arg)
        {
            case 0: return ctx.f1.f64;
            case 1: return ctx.f2.f64;
            case 2: return ctx.f3.f64;
            case 3: return ctx.f4.f64;
            case 4: return ctx.f5.f64;
            case 5: return ctx.f6.f64;
            case 6: return ctx.f7.f64;
            case 7: return ctx.f8.f64;
            case 8: return ctx.f9.f64;
            case 9: return ctx.f10.f64;
            case 10: return ctx.f11.f64;
            case 11: return ctx.f12.f64;
            case 12: return ctx.f13.f64;
            [[unlikely]] default: break;
        }

        // TODO: get value from stack.
        return 0;
    }

    constexpr static void SetIntegerArgumentValue(PPCContext& ctx, uint8_t* base, size_t arg, uint64_t value) noexcept
    {
        if (arg <= 7)
        {
            switch (arg)
            {
                case 0: ctx.r3.u64 = value; return;
                case 1: ctx.r4.u64 = value; return;
                case 2: ctx.r5.u64 = value; return;
                case 3: ctx.r6.u64 = value; return;
                case 4: ctx.r7.u64 = value; return;
                case 5: ctx.r8.u64 = value; return;
                case 6: ctx.r9.u64 = value; return;
                case 7: ctx.r10.u64 = value; return;
                [[unlikely]] default: break;
            }
        }

        assert(arg < 7 && "Pushing to stack memory is not yet supported.");
    }

    static void SetPrecisionArgumentValue(PPCContext& ctx, uint8_t* base, size_t arg, double value) noexcept
    {
        switch (arg)
        {
            case 0: ctx.f1.f64 = value; return;
            case 1: ctx.f2.f64 = value; return;
            case 2: ctx.f3.f64 = value; return;
            case 3: ctx.f4.f64 = value; return;
            case 4: ctx.f5.f64 = value; return;
            case 5: ctx.f6.f64 = value; return;
            case 6: ctx.f7.f64 = value; return;
            case 7: ctx.f8.f64 = value; return;
            case 8: ctx.f9.f64 = value; return;
            case 9: ctx.f10.f64 = value; return;
            case 10: ctx.f11.f64 = value; return;
            case 11: ctx.f12.f64 = value; return;
            case 12: ctx.f13.f64 = value; return;
            [[unlikely]] default: break;
        }

        assert(arg < 12 && "Pushing to stack memory is not yet supported.");
    }

    template<typename T>
    constexpr static std::enable_if_t<!std::is_pointer_v<T>, T> GetValue(PPCContext& ctx, uint8_t* base, size_t idx) noexcept
    {
        if constexpr (is_precise_v<T>)
        {
            return static_cast<T>(GetPrecisionArgumentValue(ctx, base, idx));
        }
        else
        {
            return static_cast<T>(GetIntegerArgumentValue(ctx, base, idx));
        }
    }

    template<typename T>
    constexpr static std::enable_if_t<std::is_pointer_v<T>, T> GetValue(PPCContext& ctx, uint8_t* base, size_t idx) noexcept
    {
        const auto v = GetIntegerArgumentValue(ctx, base, idx);
        if (!v)
        {
            return nullptr;
        }

        const uint32_t off = static_cast<uint32_t>(v);
        // Allow low guest offsets; we no longer guard the first page.
        if (off == 0 || off >= PPC_MEMORY_SIZE)
        {
            return nullptr;
        }

        return reinterpret_cast<T>(base + off);
    }

    template<typename T>
    constexpr static std::enable_if_t<!std::is_pointer_v<T>, void> SetValue(PPCContext& ctx, uint8_t* base, size_t idx, T value) noexcept
    {
        if constexpr (is_precise_v<T>)
        {
            SetPrecisionArgumentValue(ctx, base, idx, value);
        }
        else if constexpr (std::is_null_pointer_v<T>)
        {
            SetIntegerArgumentValue(ctx, base, idx, 0);
        }
        else if constexpr (std::is_pointer_v<T>)
        {
            SetIntegerArgumentValue(ctx, base, idx, g_memory.MapVirtual(value));
        }
        else
        {
            SetIntegerArgumentValue(ctx, base, idx, value);
        }
    }

    template<typename T>
    constexpr static std::enable_if_t<std::is_pointer_v<T>, void> SetValue(PPCContext& ctx, uint8_t* base, size_t idx, T value) noexcept
    {
        const auto v = g_memory.MapVirtual((void*)value);
        if (!v)
        {
            return;
        }

        SetValue(ctx, base, idx, v);
    }
};

struct Argument
{
    int type{};
    int ordinal{};
};

template<typename T1>
constexpr std::array<Argument, std::tuple_size_v<T1>> GatherFunctionArguments(const T1& tpl)
{
    std::array<Argument, std::tuple_size_v<T1>> args{};

    int floatOrdinal{};
    size_t i{};

    if constexpr (!args.empty())
    {
        std::apply([&](const auto& first, const auto&... rest)
            {
                auto append = [&]<typename T2>(const T2& v)
                {
                    if constexpr (is_precise_v<T2>)
                    {
                        args[i] = { 1, floatOrdinal++ };
                    }
                    else
                    {
                        args[i] = { 0, static_cast<int>(i) }; // what the fuck
                    }

                    i++;
                };

                append(first);
                (append(rest), ...);
            }, tpl);
    }

    return args;
}

template<auto Func>
constexpr std::array<Argument, arg_count_t<Func>::value> GatherFunctionArguments()
{
    // Use decayed types here to avoid references in tuples
    using args_decay_t = typename function_traits<decltype(Func)>::args_tuple_decay;
    return GatherFunctionArguments(args_decay_t{});
}

template<auto Func, size_t I>
struct arg_ordinal_t
{
    static constexpr size_t value = GatherFunctionArguments<Func>()[I].ordinal;
};

template<auto Func, int I = 0, typename ...TArgs>
void _translate_args_to_host(PPCContext& ctx, uint8_t* base, std::tuple<TArgs...>&) noexcept
    requires (I >= sizeof...(TArgs))
{
}

template <auto Func, int I = 0, typename ...TArgs>
std::enable_if_t<(I < sizeof...(TArgs)), void> _translate_args_to_host(PPCContext& ctx, uint8_t* base, std::tuple<TArgs...>& tpl) noexcept
{
    using T = std::tuple_element_t<I, std::remove_reference_t<decltype(tpl)>>;
    std::get<I>(tpl) = ArgTranslator::GetValue<T>(ctx, base, arg_ordinal_t<Func, I>::value);

    _translate_args_to_host<Func, I + 1>(ctx, base, tpl);
}

template<int I = 0, typename ...TArgs>
void _translate_args_to_guest(PPCContext& ctx, uint8_t* base, std::tuple<TArgs...>&) noexcept
    requires (I >= sizeof...(TArgs))
{
}

template <int I = 0, typename ...TArgs>
std::enable_if_t<(I < sizeof...(TArgs)), void> _translate_args_to_guest(PPCContext& ctx, uint8_t* base, std::tuple<TArgs...>& tpl) noexcept
{
    using T = std::tuple_element_t<I, std::remove_reference_t<decltype(tpl)>>;
    ArgTranslator::SetValue<T>(ctx, base, GatherFunctionArguments(std::tuple<TArgs...>{})[I].ordinal, std::get<I>(tpl));

    _translate_args_to_guest<I + 1>(ctx, base, tpl);
}

template<auto Func>
PPC_FUNC(HostToGuestFunction) 
{
    // Block printf-family (variadic) targets from using this generic bridge
    static_assert(!is_variadic_fp<decltype(Func)>::value,
                  "Variadic functions (printf family) cannot be routed via HostToGuestFunction. "
                  "Write a PPC_FUNC shim instead.");

    if constexpr(is_ppc_func_ptr<decltype(Func)>::value) 
    {
        // Direct PPC trampoline: no argument translation
        KernelTraceHostBegin(ctx);
        Func(ctx, base);
        KernelTraceHostEnd();
    } 
    else 
    {
        using ret_t = typename function_traits<decltype(Func)>::return_type;

        auto args = function_args(Func);
        _translate_args_to_host<Func>(ctx, base, args);
        // Expose ctx to host-side tracers for the duration of the host call
        KernelTraceHostBegin(ctx);

        if constexpr(std::is_same_v<ret_t, void>) {
            std::apply(Func, args);
            KernelTraceHostEnd();
        } 
        else 
        {
            auto v = std::apply(Func, args);
            KernelTraceHostEnd();

            if constexpr(std::is_pointer_v<ret_t>) {
                if(v != nullptr) {
                    ctx.r3.u64 = static_cast<uint32_t>(
                                     reinterpret_cast<size_t>(v) -
                                     reinterpret_cast<size_t>(base));
                } 
                else 
                {
                    ctx.r3.u64 = 0;
                }
            } 
            else if constexpr(is_precise_v<ret_t>) 
            {
                ctx.f1.f64 = v;
            } 
            else 
            {
                ctx.r3.u64 = static_cast<uint64_t>(v);
            }
        }
    }
}

template<typename T, typename TFunction, typename... TArgs>
T GuestToHostFunction(const TFunction& func, TArgs&&... argv)
{
    auto args = std::make_tuple(std::forward<TArgs>(argv)...);
    auto& currentCtx = *GetPPCContext();

    PPCContext newCtx; // NOTE: No need for zero initialization, has lots of unnecessary code generation.
    newCtx.r1 = currentCtx.r1;
    newCtx.r13 = currentCtx.r13;
    newCtx.fpscr = currentCtx.fpscr;

    _translate_args_to_guest(newCtx, g_memory.base, args);

    SetPPCContext(newCtx);

    if constexpr (std::is_function_v<TFunction>)
    {
        func(newCtx, g_memory.base);
    }
    else
    {
        // Skip if this is the host default VD ISR sentinel (not a guest function)
        if constexpr (std::is_integral_v<TFunction>) {
            if (func == Mw05GetHostDefaultVdIsrMagic()) {
                KernelTraceHostOp("HOST.GuestToHostFunction.skip.host_isr");
            } else {
                // CRITICAL DEBUG: Check function table entry directly
                uint64_t code_offset = uint64_t(uint32_t(func) - uint32_t(PPC_CODE_BASE));
                uint64_t table_offset = PPC_MEMORY_SIZE + (code_offset * sizeof(PPCFunc*));
                PPCFunc** funcPtrAddr = reinterpret_cast<PPCFunc**>(g_memory.base + table_offset);
                PPCFunc* funcPtr = *funcPtrAddr;

                if (funcPtr) {
                    funcPtr(newCtx, g_memory.base);
                } else {
                    // Function table entry is NULL - this is the real problem!
                    fprintf(stderr, "[boot][error] Guest function 0x%08X not found in function table.\n", func);
                    fprintf(stderr, "[boot][error] code_offset=0x%llX table_offset=0x%llX\n",
                            (unsigned long long)code_offset, (unsigned long long)table_offset);
                    fprintf(stderr, "[boot][error] funcPtrAddr=%p funcPtr=%p\n", funcPtrAddr, funcPtr);
                    fprintf(stderr, "[boot][error] This means the function was not registered via InsertFunction().\n");
                    fprintf(stderr, "[boot][error] Check if manual hooks constructor ran before this call.\n");
                    fflush(stderr);
                }
            }
        } else if (auto guestFunc = g_memory.FindFunction(func)) {
            guestFunc(newCtx, g_memory.base);
        } else {
            fprintf(stderr, "[boot][error] Guest function not found.\n");
        }
    }

    currentCtx.fpscr = newCtx.fpscr;
    SetPPCContext(currentCtx);

    if constexpr (std::is_pointer_v<T>)
    {
        return reinterpret_cast<T>((uint64_t)g_memory.Translate(newCtx.r3.u32));
    }
    else if constexpr (is_precise_v<T>)
    {
        return static_cast<T>(newCtx.f1.f64);
    }
    else if constexpr (std::is_integral_v<T>)
    {
        return static_cast<T>(newCtx.r3.u64);
    }
    else
    {
        static_assert(std::is_void_v<T>, "Unsupported return type.");
    }
}

#define GUEST_FUNCTION_HOOK(subroutine, function) \
    PPC_FUNC(subroutine) { KernelTraceImport(#subroutine, ctx); HostToGuestFunction<function>(ctx, base); }

#define GUEST_FUNCTION_STUB(subroutine) \
    PPC_FUNC(subroutine) { }
